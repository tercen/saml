// PII guard: the exc-c14n canonicalization path used to carry a bare
// `print` that dumped the full canonicalized Assertion — NameID (user
// email) + attributes — to stdout on EVERY signature validation (PII in
// pod logs). The print is removed; this test proves the silence with a
// zone-captured print handler around a REAL validation, and asserts the
// validation result itself so it cannot pass vacuously.
import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:saml/saml.dart';
import 'package:test/test.dart';

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

String metadataDocument(String cert) => '''
<EntityDescriptor
    ID="_feda1bd8-6f52-4e0b-8fbc-1b16bd0ef902"
    entityID="$azureIdpIssuer"
    xmlns="urn:oasis:names:tc:SAML:2.0:metadata">
  <IDPSSODescriptor
      protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <KeyDescriptor use="signing">
      <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
        <X509Data><X509Certificate>$cert</X509Certificate></X509Data>
      </KeyInfo>
    </KeyDescriptor>
    <SingleSignOnService
        Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
        Location="$azureBindingUrl"/>
  </IDPSSODescriptor>
</EntityDescriptor>
''';

void main() {
  test('validateResponse emits ZERO stdout prints (PII guard)', () async {
    final saml = await Saml.fromMetadata(metadataDocument(bareBase64(
        'test/azure-ad-cert.pem')), azureRequestIssuer, azureAudience);

    final captured = <String>[];
    // validateResponse is synchronous: the whole canonicalization +
    // verification path runs inside the zone, so a print anywhere on it
    // would be captured.
    final validated = runZoned(
        () => saml.validateResponse(SamlResponse(azureResponse),
            validateTime: false),
        zoneSpecification: ZoneSpecification(
            print: (self, parent, zone, line) => captured.add(line)));

    // non-vacuous: the validation actually ran, exercised the canonicalizer
    // (exc-c14n runs for every signature verification) and PASSED — yet
    // nothing reached stdout.
    expect(validated, isTrue);
    expect(captured, isEmpty);
  });
}
