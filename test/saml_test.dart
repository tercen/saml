import 'package:saml/saml.dart';
import 'package:test/test.dart';

void main() {
  group('A group of tests', () {
    String RESPONSE =
        '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Destination="http://127.0.0.1:5400/_service/sso/auth/saml" ID="ID_482c7258-fcc5-45e3-8768-b70b8e71b762" InResponseTo="id43ae8ce140146bb195885df8410176ca" IssueInstant="2022-02-18T10:41:27.558Z" Version="2.0"><saml:Issuer>http://127.0.0.1:8080/auth/realms/tercen</saml:Issuer><dsig:Signature xmlns:dsig="http://www.w3.org/2000/09/xmldsig#"><dsig:SignedInfo><dsig:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><dsig:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><dsig:Reference URI="#ID_482c7258-fcc5-45e3-8768-b70b8e71b762"><dsig:Transforms><dsig:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><dsig:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></dsig:Transforms><dsig:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><dsig:DigestValue>SnGPfKQCEexiwl6kscd4zmVyVFGlvagAjJuAhiOrCFs=</dsig:DigestValue></dsig:Reference></dsig:SignedInfo><dsig:SignatureValue>iINynNqUY0UsO1mC0VLMgN1DK6JywgKU9UaWODTjWA4V3uCSRQvjmpdoNT4OrbRVmES2q7FJ3BN7mibgmOKpaQJhTI/UR7Kv/ccxdtTGSatC5bhikcgilRf/hvTyJSHdIXGkir72OCjkgErq+aU++wH9BQLUw7MVVhP3f8YWnAU8/aEG8BkuSj5I4MnOMuZN5ucCbVb1sHx3FkUqh3GgyZ+VWI2W2M4J5vd6gxNGYcKSSMAeEVcfi/woSZmrRgT8ekMROvP0ZXAQzxmRFpUxlKYPWcLSESWvUqZveh0+270ZhjR3TSAFt3+5xEIA7hLf37zPHgmKBfovKothd4pf5w==</dsig:SignatureValue><dsig:KeyInfo><dsig:KeyName>8fDJYDhF_rq5fmN2333g8F2eZCjbOz_4R2OJGgYS-mA</dsig:KeyName><dsig:X509Data><dsig:X509Certificate>MIICmzCCAYMCBgF+5JNuKzANBgkqhkiG9w0BAQsFADARMQ8wDQYDVQQDDAZ0ZXJjZW4wHhcNMjIwMjEwMTY1NzU0WhcNMzIwMjEwMTY1OTM0WjARMQ8wDQYDVQQDDAZ0ZXJjZW4wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCW2/pXQ9Hp+iZZnOmc7Wfq699/uEl6mL4WCAvdPVf495ro0ZDLpCcatyDypVpNWO7gwo7TWSYwAgCUiUEiheuu2mvv/e7V4raClrCMARykTb4vGuCvxoqZ5xlFtS7tSlC7H1TICNewWCk7gowYhyBpMre4tvjKN2D6jASqCrvkBCBHHwu3JIfCXzuRCwkLpnrvuyMakMGesukBJq0lqt8k5XJ/jB/WQR6vhr0FJCLioV07bzGwF0L6MWxDHbJSzuNJ7DXNAif8243Ewgb1eIqPjP+MdHopElQil6WXnKJZOjrE/sfo8ZUqT8ZnWOHaCpzXiARE69sElySS7rj8LKZNAgMBAAEwDQYJKoZIhvcNAQELBQADggEBAE2bizV2h4s7iAe5ONUSTdkKSJM6xD+pPctEAZwCFn2tNpreNqYOvPmzMMq3telk5BFKvqTXLXJlyKkdnEuoRKEK0ZZljNHejZ9OXJpxr7a4PmCldxOKfrwynGxbDhNCrRlFZNZCENqpzZU1IMfI+IVTMjrXSmGiBR6rutczKPH1MVS2HVW+PXsCx+LKxOugYsPp2689I/fIHkzz4D5ZSZ7++l9i9It3SLt2AC4KcioknFVVjGFjhrnzy175iWoYjD6u1dCTQ9UDLxIdFzuGWHXCfImHQKKAJcvDtxGWGB566H8g3amQCezFBdtwCi57St3DH6oxzfSQGDYxj+IYWRA=</dsig:X509Certificate></dsig:X509Data><dsig:KeyValue><dsig:RSAKeyValue><dsig:Modulus>ltv6V0PR6fomWZzpnO1n6uvff7hJepi+FggL3T1X+Pea6NGQy6QnGrcg8qVaTVju4MKO01kmMAIAlIlBIoXrrtpr7/3u1eK2gpawjAEcpE2+Lxrgr8aKmecZRbUu7UpQux9UyAjXsFgpO4KMGIcgaTK3uLb4yjdg+owEqgq75AQgRx8LtySHwl87kQsJC6Z677sjGpDBnrLpASatJarfJOVyf4wf1kEer4a9BSQi4qFdO28xsBdC+jFsQx2yUs7jSew1zQIn/NuNxMIG9XiKj4z/jHR6KRJUIpell5yiWTo6xP7H6PGVKk/GZ1jh2gqc14gEROvbBJckku64/CymTQ==</dsig:Modulus><dsig:Exponent>AQAB</dsig:Exponent></dsig:RSAKeyValue></dsig:KeyValue></dsig:KeyInfo></dsig:Signature><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status><saml:Assertion xmlns="urn:oasis:names:tc:SAML:2.0:assertion" ID="ID_ee3a170b-5eb1-45fa-b5b2-137ae1ba8170" IssueInstant="2022-02-18T10:41:27.558Z" Version="2.0"><saml:Issuer>http://127.0.0.1:8080/auth/realms/tercen</saml:Issuer><saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">alexandre.maurel@gmail.com</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData InResponseTo="id43ae8ce140146bb195885df8410176ca" NotOnOrAfter="2022-02-18T10:46:25.558Z" Recipient="http://127.0.0.1:5400/_service/sso/auth/saml"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="2022-02-18T10:41:25.558Z" NotOnOrAfter="2022-02-18T10:42:25.558Z"><saml:AudienceRestriction><saml:Audience>http://127.0.0.1:5400/_service/sso/auth/saml</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AuthnStatement AuthnInstant="2022-02-18T10:41:27.558Z" SessionIndex="ee6d056e-1efc-4695-98d3-60f5d36257bb::573e07c0-a0ef-4cd2-8485-c8f8cddcdba9" SessionNotOnOrAfter="2022-02-18T20:41:27.558Z"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement><saml:AttributeStatement><saml:Attribute Name="Role" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"><saml:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">default-roles-tercen</saml:AttributeValue></saml:Attribute><saml:Attribute Name="Role" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"><saml:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">offline_access</saml:AttributeValue></saml:Attribute><saml:Attribute Name="Role" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"><saml:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">manage-account</saml:AttributeValue></saml:Attribute><saml:Attribute Name="Role" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"><saml:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">view-profile</saml:AttributeValue></saml:Attribute><saml:Attribute Name="Role" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"><saml:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">manage-account-links</saml:AttributeValue></saml:Attribute><saml:Attribute Name="Role" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"><saml:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">uma_authorization</saml:AttributeValue></saml:Attribute></saml:AttributeStatement></saml:Assertion></samlp:Response>';

    String ISSUER = 'http://127.0.0.1:8080/auth/realms/tercen';
    String AUDIENCE = 'http://127.0.0.1:5400/_service/sso/auth/saml';

    setUp(() {});

    test('First Test', () async {
      var saml =
          await Saml.fromCertificatePemFile('test/cert.pem', ISSUER, AUDIENCE);

      final response = SamlResponse(RESPONSE);

      expect(saml.validateResponse(response, validateTime: false), isTrue);

      expect(saml.validateResponse(response, validateTime: true), isFalse);

      saml =
          await Saml.fromCertificatePemFile('test/cert.pem', 'dummy', AUDIENCE);

      expect(saml.validateResponse(response, validateTime: false), isFalse);

      saml =
          await Saml.fromCertificatePemFile('test/cert.pem', ISSUER, 'dummy');

      expect(saml.validateResponse(response, validateTime: false), isFalse);
    });
  });
}