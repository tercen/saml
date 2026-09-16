// Multi-value attribute access: IdPs like Entra ID emit app-role claims as
// a single <Attribute> carrying multiple <AttributeValue> children. The
// plural getter must surface ALL of them; the singular getter stays
// first-value (compatibility with the email-claim path).
//
// Parsing-only: attribute extraction does not depend on signature
// validation, so an unsigned response isolates the model under test.
import 'package:saml/saml.dart';
import 'package:test/test.dart';

const String responseXml = '''
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    ID="_resp" Version="2.0" IssueInstant="2026-09-16T12:00:00Z">
  <saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
    https://sts.windows.net/5b5c94c6-14cf-42da-85bc-4e08722b253b/
  </saml:Issuer>
  <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
      ID="_assert" Version="2.0" IssueInstant="2026-09-16T12:00:00Z">
    <saml:Issuer>https://sts.windows.net/5b5c94c6-14cf-42da-85bc-4e08722b253b/</saml:Issuer>
    <saml:AttributeStatement>
      <saml:Attribute
          Name="http://schemas.microsoft.com/ws/2008/06/identity/claims/role">
        <saml:AttributeValue>iQue-Admin</saml:AttributeValue>
        <saml:AttributeValue>iQue-User</saml:AttributeValue>
      </saml:Attribute>
      <saml:Attribute Name="email">
        <saml:AttributeValue>user@sartorius.com</saml:AttributeValue>
      </saml:Attribute>
    </saml:AttributeStatement>
  </saml:Assertion>
</samlp:Response>
''';

void main() {
  test('attributeValues exposes EVERY value of a multi-value claim',
      () {
    final response = SamlResponse(responseXml);

    final roleClaim = response.assertions.first.attributeStatement!.attributes
        .firstWhere((a) => a.name.endsWith('/claims/role'));

    expect(
      roleClaim.attributeValues.map((v) => v.value),
      ['iQue-Admin', 'iQue-User'],
    );
  });

  test('attributeValue stays first-value (email-path compatibility)', () {
    final response = SamlResponse(responseXml);

    final statement = response.assertions.first.attributeStatement!;

    final roleClaim = statement.attributes
        .firstWhere((a) => a.name.endsWith('/claims/role'));
    expect(roleClaim.attributeValue.value, 'iQue-Admin');

    final email = statement.attributes.firstWhere((a) => a.name == 'email');
    expect(email.attributeValue.value, 'user@sartorius.com');
  });
}
