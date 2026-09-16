import 'dart:convert';
import 'dart:io';

import 'package:saml/saml.dart';
import 'package:test/test.dart';

void main() {
  group('A group of tests', () {
    // azure AD
    String AZURE_RESPONSE =
        File('./test/response/azure_ad_response_raw.xml').readAsStringSync();
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

    test('Inline certificate value test', () async {
      for (var config in samlConfigs) {
        String response = config['RESPONSE']!;
        String issuer = config['ISSUER']!;
        String bindingUrl = config['BINDING_URL']!;
        String audience = config['AUDIENCE']!;
        String requestIssuer = config['REQUEST_ISSUER']!;
        String certContent =
            File(config['CERT_FILE']!).readAsStringSync();

        String base64Body = LineSplitter.split(certContent)
            .map((line) => line.trim())
            .where((line) => line.isNotEmpty && !line.startsWith('-----'))
            .join();

        // bare base64 DER, single line
        var saml = await Saml.fromCertificatePem(
            base64Body, issuer, audience, bindingUrl, requestIssuer);
        expect(
            saml.validateResponse(SamlResponse(response), validateTime: false),
            isTrue);

        // bare base64 DER, broken into short lines with whitespace
        // (the form IdP federation metadata embeds in X509Certificate)
        var wrapped = RegExp('.{1,32}').allMatches(base64Body).map((m) => m.group(0)).join('\n');
        saml = await Saml.fromCertificatePem(
            wrapped, issuer, audience, bindingUrl, requestIssuer);
        expect(
            saml.validateResponse(SamlResponse(response), validateTime: false),
            isTrue);

        // PEM-armoured string — same outcome as the file constructor
        saml = await Saml.fromCertificatePem(
            certContent, issuer, audience, bindingUrl, requestIssuer);
        expect(
            saml.validateResponse(SamlResponse(response), validateTime: false),
            isTrue);

        // validation still rejects a wrong issuer / audience
        saml = await Saml.fromCertificatePem(
            base64Body, 'dummy', audience, bindingUrl, requestIssuer);
        expect(
            saml.validateResponse(SamlResponse(response), validateTime: false),
            isFalse);

        saml = await Saml.fromCertificatePem(
            base64Body, issuer, 'dummy', bindingUrl, requestIssuer);
        expect(
            saml.validateResponse(SamlResponse(response), validateTime: false),
            isFalse);
      }

      // no certificate content — construction throws
      expect(
          () async => await Saml.fromCertificatePem(
              'not-a-certificate',
              AZURE_ISSUER,
              AZURE_AUDIENCE,
              AZURE_BINDING_URL,
              AZURE_REQUEST_ISSUER),
          throwsFormatException);
    });
  });
}
