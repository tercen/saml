import 'dart:io';

import 'package:saml/saml.dart';
import 'package:test/test.dart';

void main() {
  group('A group of tests', () {
    // azure AD
    String AZURE_RESPONSE =
        '<samlp:Response ID="_26f81b2a-e699-4f99-be44-e2814d1bef52" Version="2.0" IssueInstant="2022-02-23T17:49:18.872Z" Destination="https://devpg.tercen.com/_service/sso/auth/saml" InResponseTo="id6491e192-e2d9-4970-ab03-e38ffda6e033" xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"><Issuer xmlns="urn:oasis:names:tc:SAML:2.0:assertion">https://sts.windows.net/5b5c94c6-14cf-42da-85bc-4e08722b253b/</Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status><Assertion ID="_8c68ecbc-f68b-4f9b-bf66-e6afe9c0b001" IssueInstant="2022-02-23T17:49:18.872Z" Version="2.0" xmlns="urn:oasis:names:tc:SAML:2.0:assertion"><Issuer>https://sts.windows.net/5b5c94c6-14cf-42da-85bc-4e08722b253b/</Issuer><Signature xmlns="http://www.w3.org/2000/09/xmldsig#"><SignedInfo><CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><Reference URI="#_8c68ecbc-f68b-4f9b-bf66-e6afe9c0b001"><Transforms><Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></Transforms><DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><DigestValue>4l74y+qS9+zCCIiZtmbxfC/e92YyQ6/U4XeMBXtKMfQ=</DigestValue></Reference></SignedInfo><SignatureValue>KQ6TXajgiwuzflGQBhhbYTDjdTH4JBoNqn8bGT3U7gdeNn9OGmuHAirua3aqwWUaETd1Xl5yX61Rd5SiX+qp00wdqMGy/25vEfA6EwEem2T2gn5htcuTzsn4FnRq8tr2LflIBNoCH9VgWVTkG1cXfY1xu+UwCrUEUjJSixVANHzp0UoA7k8cuBLGfkqltpkBXeB6dr9pIuX6d9VZbdwI83HC36pBhRIuKipkUpcye441OIJbIj2yfRJ03YZnNMynRNBpIg7/pXeEtOABsR9QdETWeKsFasA0kF3laEZsRXDHN5jkwLsj1crUcXmLX/GOyvi104kZCAEHaP1dn5cFhQ==</SignatureValue><KeyInfo><X509Data><X509Certificate>MIIC8DCCAdigAwIBAgIQGKJCRqQqqYhF69tbYp0/NDANBgkqhkiG9w0BAQsFADA0MTIwMAYDVQQDEylNaWNyb3NvZnQgQXp1cmUgRmVkZXJhdGVkIFNTTyBDZXJ0aWZpY2F0ZTAeFw0yMjAyMjMwOTIxMzdaFw0yNTAyMjMwOTIxMzdaMDQxMjAwBgNVBAMTKU1pY3Jvc29mdCBBenVyZSBGZWRlcmF0ZWQgU1NPIENlcnRpZmljYXRlMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxnS2mMMQ+LNsj0apk9t0aMwmgbdVQHWvR4pgyhG3ztvK+lodjg0DZpzX7pwOv8ahJ7syz54lGQccf4MjMbuJut4+vLk7KGeJOP/vGlBy+E9kFRXxxzvXbnkR64c4z7QKZXjXRLfSq58pJd/MYrhX7jGRyVo8u1QFspiuMbo4KooKIJ3wrIxkDXF2r39xufaKOjB3q8SKoOAWA1Yb3r2q4SxqGed8JlzF3RnijQFPa8YgU53XAHEWG1gMYWiwID3YauKCVl9go9zMMj8fsnMEz6UIwaLZ3wUODFyRmwEkRvk1Qi/MhPqryqO5UMsObH9d2LpzwjPvH82Txo7xrvc1SQIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQBlQotwm8WY+2GYGhE112qC5yV80IHk/QB5aJM6o1UWBTddf0On/TneEVUfoNXAl+MiFH5CRN3X+noRRuQ7LGHXa6xkhSnY3Rj4KuENHQPerCCMND9tSdSpJVHSN/AvTD3p6zhvl942O9Pvd3BRlL6ID7tYZdf3gmSfcTfhwsDveaoCql0ZfhGh2Y5xD80rzHb6mpjMp7weJfEJ4w2QcO1iKn7hP6hn7UrU97/+BiUfneh3E8s2T5wV3oXC3zC8t5y7NeKhRRUBMDBko9PI6e51/oBJKKyqtSfYDZpiASur53e5bCsV4sbsaIEX/jm8OAbRSi4fVLNr4sYh107TfGFC</X509Certificate></X509Data></KeyInfo></Signature><Subject><NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">test@alexandremaurelgmail.onmicrosoft.com</NameID><SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><SubjectConfirmationData InResponseTo="id6491e192-e2d9-4970-ab03-e38ffda6e033" NotOnOrAfter="2022-02-23T18:49:18.779Z" Recipient="https://devpg.tercen.com/_service/sso/auth/saml"/></SubjectConfirmation></Subject><Conditions NotBefore="2022-02-23T17:44:18.779Z" NotOnOrAfter="2022-02-23T18:49:18.779Z"><AudienceRestriction><Audience>https://devpg.tercen.com/_service/sso/auth/saml</Audience></AudienceRestriction></Conditions><AttributeStatement><Attribute Name="http://schemas.microsoft.com/identity/claims/tenantid"><AttributeValue>5b5c94c6-14cf-42da-85bc-4e08722b253b</AttributeValue></Attribute><Attribute Name="http://schemas.microsoft.com/identity/claims/objectidentifier"><AttributeValue>814bd554-6a00-405c-91d5-4132d39ba4fb</AttributeValue></Attribute><Attribute Name="http://schemas.microsoft.com/identity/claims/displayname"><AttributeValue>test</AttributeValue></Attribute><Attribute Name="http://schemas.microsoft.com/identity/claims/identityprovider"><AttributeValue>https://sts.windows.net/5b5c94c6-14cf-42da-85bc-4e08722b253b/</AttributeValue></Attribute><Attribute Name="http://schemas.microsoft.com/claims/authnmethodsreferences"><AttributeValue>http://schemas.microsoft.com/ws/2008/06/identity/authenticationmethod/password</AttributeValue></Attribute><Attribute Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name"><AttributeValue>test@alexandremaurelgmail.onmicrosoft.com</AttributeValue></Attribute></AttributeStatement><AuthnStatement AuthnInstant="2022-02-23T10:17:10.452Z" SessionIndex="_8c68ecbc-f68b-4f9b-bf66-e6afe9c0b001"><AuthnContext><AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</AuthnContextClassRef></AuthnContext></AuthnStatement></Assertion></samlp:Response>';
    String AZURE_ISSUER =
        'https://sts.windows.net/5b5c94c6-14cf-42da-85bc-4e08722b253b/';
    String AZURE_BINDING_URL =
        'https://login.microsoftonline.com/5b5c94c6-14cf-42da-85bc-4e08722b253b/saml2';
    String AZURE_AUDIENCE = 'https://devpg.tercen.com/_service/sso/auth/saml';
    String AZURE_REQUEST_ISSUER =
        'https://devpg.tercen.com/_service/sso/auth/saml';
    String AZURE_CERT_FILE = 'test/azure-ad-cert.pem';

    // keycloak
    String KEYCLOAK_RESPONSE =
        File('./test/response/keycloak_response_raw.xml').readAsStringSync();
    String KEYCLOAK_ISSUER = 'http://127.0.0.1:8080/auth/realms/tercen';
    String KEYCLOAK_BINDING_URL = 'http://127.0.0.1:8080/auth/realms/tercen';
    String KEYCLOAK_AUDIENCE = 'http://127.0.0.1:5400/_service/sso/auth/saml';
    String KEYCLOAK_REQUEST_ISSUER =
        'http://127.0.0.1:5400/_service/sso/auth/saml';
    String KEYCLOAK_CERT_FILE = 'test/cert.pem';

    List<Map<String, String>> samlConfigs = [
      {
        'RESPONSE': AZURE_RESPONSE,
        'ISSUER': AZURE_ISSUER,
        'BINDING_URL': AZURE_BINDING_URL,
        'AUDIENCE': AZURE_AUDIENCE,
        'REQUEST_ISSUER': AZURE_REQUEST_ISSUER,
        'CERT_FILE': AZURE_CERT_FILE,
      },
      {
        'RESPONSE': KEYCLOAK_RESPONSE,
        'ISSUER': KEYCLOAK_ISSUER,
        'BINDING_URL': KEYCLOAK_BINDING_URL,
        'AUDIENCE': KEYCLOAK_AUDIENCE,
        'REQUEST_ISSUER': KEYCLOAK_REQUEST_ISSUER,
        'CERT_FILE': KEYCLOAK_CERT_FILE,
      }
    ];

    setUp(() {});

    test('First Test', () async {
      for (var config in samlConfigs) {
        String response = config['RESPONSE']!;
        String issuer = config['ISSUER']!;
        String bindingUrl = config['BINDING_URL']!;
        String audience = config['AUDIENCE']!;
        String requestIssuer = config['REQUEST_ISSUER']!;
        String certFile = config['CERT_FILE']!;

        var saml = await Saml.fromCertificatePemFile(
            certFile, issuer, audience, bindingUrl, requestIssuer);

        final saml_response = SamlResponse(response);

        expect(
            saml.validateResponse(saml_response, validateTime: false), isTrue);

        expect(
            saml.validateResponse(saml_response, validateTime: true), isFalse);

        saml = await Saml.fromCertificatePemFile(
            certFile, 'dummy', audience, bindingUrl, requestIssuer);

        expect(
            saml.validateResponse(saml_response, validateTime: false), isFalse);

        saml = await Saml.fromCertificatePemFile(
            certFile, issuer, 'dummy', bindingUrl, requestIssuer);

        expect(
            saml.validateResponse(saml_response, validateTime: false), isFalse);
      }
    });

    test('Role Assertion Test', () async {
      var samlResponse = SamlResponse(KEYCLOAK_RESPONSE);
      var attributeName = 'Role';
      var attributeValues = samlResponse.assertions
          .map((element) => element.attributeStatement)
          .where((element) => element != null)
          .cast<AttributeStatement>()
          .expand((element) => element.attributes)
          .where((element) => element.name == attributeName)
          .map((e) => e.attributeValue.value);

      expect(attributeValues.toList(), [
        "default-roles-tercen",
        "offline_access",
        "manage-account",
        "view-profile",
        "manage-account-links",
        "uma_authorization"
      ]);
    });
  });
}
