// Metadata ingestion tests: SamlMetadata.parse + Saml.fromMetadata +
// multi-key verification (tercen/sci#1602 main deliverable).
//
// The fixture is Entra-federation-metadata-shaped: EntityDescriptor with
// entityID, an IDPSSODescriptor carrying MULTIPLE use="signing"
// KeyDescriptor elements (the rollover shape), an encryption KeyDescriptor
// that must be ignored, and both HTTP-Redirect and HTTP-POST
// SingleSignOnService entries (Redirect wins).
//
// "Old" key = the Azure AD test certificate that actually signed the stored
// Azure response; "new" key = the Keycloak test certificate — a different
// RSA key advertised next to the old one, exactly like an IdP rollover
// window.
import 'dart:convert';
import 'dart:io';

import 'package:saml/saml.dart';
import 'package:test/test.dart';
import 'package:xml/xml.dart';

const String azureIdpIssuer =
    'https://sts.windows.net/5b5c94c6-14cf-42da-85bc-4e08722b253b/';
const String azureBindingUrl =
    'https://login.microsoftonline.com/5b5c94c6-14cf-42da-85bc-4e08722b253b/saml2';
const String azureAudience =
    'https://devpg.tercen.com/_service/sso/auth/saml';
const String azureRequestIssuer =
    'https://devpg.tercen.com/_service/sso/auth/saml';

final String azureResponse =
    File('./test/response/azure_ad_response_raw.xml').readAsStringSync();

String bareBase64(String path) {
  final content = File(path).readAsStringSync();
  return LineSplitter.split(content)
      .map((line) => line.trim())
      .where((line) => line.isNotEmpty && !line.startsWith('-----'))
      .join();
}

String metadataDocument({
  required List<String> signingCerts,
  List<String> encryptionCerts = const [],
  bool useAttribute = true,
  String entityId = azureIdpIssuer,
}) {
  final keyDescriptors = StringBuffer();
  for (final cert in signingCerts) {
    keyDescriptors.write('''
    <KeyDescriptor${useAttribute ? ' use="signing"' : ''}>
      <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
        <X509Data><X509Certificate>$cert</X509Certificate></X509Data>
      </KeyInfo>
    </KeyDescriptor>
''');
  }
  for (final cert in encryptionCerts) {
    keyDescriptors.write('''
    <KeyDescriptor use="encryption">
      <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
        <X509Data><X509Certificate>$cert</X509Certificate></X509Data>
      </KeyInfo>
    </KeyDescriptor>
''');
  }

  return '''
<EntityDescriptor
    ID="_feda1bd8-6f52-4e0b-8fbc-1b16bd0ef902"
    entityID="$entityId"
    xmlns="urn:oasis:names:tc:SAML:2.0:metadata">
  <IDPSSODescriptor
      protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
$keyDescriptors    <SingleSignOnService
        Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
        Location="$azureBindingUrl"/>
    <SingleSignOnService
        Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
        Location="$azureBindingUrl"/>
  </IDPSSODescriptor>
</EntityDescriptor>
''';
}

String metadataWithoutRedirect() {
  return '''
<EntityDescriptor
    entityID="$azureIdpIssuer"
    xmlns="urn:oasis:names:tc:SAML:2.0:metadata">
  <IDPSSODescriptor
      protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <KeyDescriptor use="signing">
      <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
        <X509Data><X509Certificate>${bareBase64('test/azure-ad-cert.pem')}</X509Certificate></X509Data>
      </KeyInfo>
    </KeyDescriptor>
    <SingleSignOnService
        Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
        Location="$azureBindingUrl"/>
  </IDPSSODescriptor>
</EntityDescriptor>
''';
}

String tamperSignatureValue(String responseXml) {
  final document = XmlDocument.parse(responseXml);
  final signatureValue = document
      .findAllElements('SignatureValue', namespace: Saml.XMLDSIG_NS)
      .first;
  // flip the signature to garbage while leaving SignedInfo + digests intact
  signatureValue.children.clear();
  signatureValue.children.add(XmlText(List.filled(344, 'A').join()));
  return document.toXmlString();
}

void main() {
  final oldCert = bareBase64('test/azure-ad-cert.pem');
  final newCert = bareBase64('test/cert.pem');

  group('SamlMetadata.parse', () {
    test('parses entityID, HTTP-Redirect binding and ALL signing certs', () {
      final metadata = SamlMetadata.parse(
          metadataDocument(signingCerts: [oldCert, newCert]));

      expect(metadata.entityId, azureIdpIssuer);
      expect(metadata.bindingUrl, azureBindingUrl);
      // both signing certs collected in order; no dedup artifacts
      expect(metadata.certificates, [oldCert, newCert]);
    });

    test('encryption KeyDescriptors are ignored, certs deduplicated', () {
      final metadata = SamlMetadata.parse(metadataDocument(
          signingCerts: [oldCert, oldCert, newCert],
          encryptionCerts: [newCert]));
      expect(metadata.certificates, [oldCert, newCert]);
    });

    test('KeyDescriptor without a use attribute counts as signing', () {
      final metadata = SamlMetadata.parse(
          metadataDocument(signingCerts: [oldCert], useAttribute: false));
      expect(metadata.certificates, [oldCert]);
    });

    test('encryption-only metadata throws', () {
      expect(
          () => SamlMetadata.parse(metadataDocument(
              signingCerts: const [], encryptionCerts: [oldCert])),
          throwsFormatException);
    });

    test('metadata without HTTP-Redirect binding throws', () {
      expect(() => SamlMetadata.parse(metadataWithoutRedirect()),
          throwsFormatException);
    });

    test('non-EntityDescriptor input throws', () {
      expect(
          () => SamlMetadata.parse(
              '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"/>'),
          throwsFormatException);
    });

    test('EntityDescriptor without entityID throws', () {
      expect(
          () => SamlMetadata.parse(
              '<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata"/>'),
          throwsFormatException);
    });
  });

  group('Saml.fromMetadata + multi-key verification', () {
    test(
        'rollover proof: response signed with the OLD key still validates '
        'while the NEW key is advertised', () async {
      final saml = await Saml.fromMetadata(
          metadataDocument(signingCerts: [oldCert, newCert]),
          azureRequestIssuer,
          azureAudience);

      expect(saml.idpIssuer, azureIdpIssuer);
      expect(saml.bindingUrl, azureBindingUrl);
      expect(
          saml.validateResponse(SamlResponse(azureResponse),
              validateTime: false),
          isTrue);
    });

    test('single advertised key keeps working', () async {
      final saml = await Saml.fromMetadata(
          metadataDocument(signingCerts: [oldCert]),
          azureRequestIssuer,
          azureAudience);
      expect(
          saml.validateResponse(SamlResponse(azureResponse),
              validateTime: false),
          isTrue);
    });

    test('tampered signature is rejected against ALL keys', () async {
      final saml = await Saml.fromMetadata(
          metadataDocument(signingCerts: [oldCert, newCert]),
          azureRequestIssuer,
          azureAudience);
      final tampered = tamperSignatureValue(azureResponse);

      expect(
          saml.validateResponse(SamlResponse(tampered), validateTime: false),
          isFalse);
    });

    test('wrong issuer / audience still rejected under multi-key', () async {
      // the IdP issuer comes FROM the metadata entityID — a document for a
      // different IdP must not validate this IdP's responses
      final wrongIssuerXml = metadataDocument(
          signingCerts: [oldCert, newCert],
          entityId: 'https://wrong.example.com/sso');
      var saml = await Saml.fromMetadata(
          wrongIssuerXml, azureRequestIssuer, azureAudience);
      expect(
          saml.validateResponse(SamlResponse(azureResponse),
              validateTime: false),
          isFalse);

      final metadataXml =
          metadataDocument(signingCerts: [oldCert, newCert]);
      saml = await Saml.fromMetadata(
          metadataXml, azureRequestIssuer, 'dummy');
      expect(
          saml.validateResponse(SamlResponse(azureResponse),
              validateTime: false),
          isFalse);
    });
  });
}
