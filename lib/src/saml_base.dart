import 'dart:io';
import 'dart:convert';
import 'dart:typed_data';
import 'package:uuid/uuid.dart';

import 'package:xml/xml.dart';

import 'package:rsa_pkcs/rsa_pkcs.dart' as rsa;
import 'package:pointycastle/export.dart';

class Saml {
  static const String SAML_PROTOCOL_NS = 'urn:oasis:names:tc:SAML:2.0:protocol';
  static const String SAML_ASSERTION_NS =
      'urn:oasis:names:tc:SAML:2.0:assertion';
  static const String SAML_METADATA_NS = 'urn:oasis:names:tc:SAML:2.0:metadata';
  static const String XMLDSIG_NS = 'http://www.w3.org/2000/09/xmldsig#';

  RSASigner _signer;

  final String _idpIssuer;
  final String _requestIssuer;
  final String _audience;
  final String _bindingUrl;

  static Future<Saml> fromCertificatePemFile(
      String certificateFile,
      String idpIssuer,
      String audience,
      String bindingUrl,
      String requestIssuer) async {
    final certFile = File(certificateFile);
    var rsaParser = rsa.RSAPKCSParser();
    final pair = rsaParser.parsePEM(await certFile.readAsString());
    var publicKey = RSAPublicKey(
        pair.public!.modulus, BigInt.from(pair.public!.publicExponent));
    final verifier = RSASigner(SHA256Digest(), '0609608648016503040201');
    verifier.init(false, PublicKeyParameter<RSAPublicKey>(publicKey)); // false=

    return Saml(
        idpIssuer, audience, verifier, bindingUrl, requestIssuer); // verify
  }

  Saml(this._idpIssuer, this._audience, this._signer, this._bindingUrl,
      this._requestIssuer);

  SamlAuthnRequest createAuthnRequest() =>
      SamlAuthnRequest.fromIssuer(_requestIssuer);
  SamlLogoutRequest createLogoutRequest(String nameId) =>
      SamlLogoutRequest.fromIssuer(_requestIssuer, nameId);

  bool _rsaVerify(Uint8List signedData, Uint8List signature) {
    final sig = RSASignature(signature);

    try {
      return _signer.verifySignature(signedData, sig);
    } on ArgumentError {
      return false; // for Pointy Castle 1.0.2 when signature has been modified
    }
  }

  String get idpIssuer => _idpIssuer;
  String get audience => _audience;
  String get bindingUrl => _bindingUrl;

  bool validateResponse(SamlResponse response, {bool validateTime: true}) {
    if (response.issuer != _idpIssuer) {
      return false;
    }

    for (var assertion in response.assertions) {
      if (!assertion.validate(idpIssuer, audience,
          validateTime: validateTime)) {
        return false;
      }
    }

    if (!validateSignature(response)) {
      return false;
    }

    if (!validateDigests(response)) {
      return false;
    }

    return true;
  }

  bool validateSignature(SamlResponse response) {
    return response.signatures.any((signature) => _rsaVerify(
        utf8.encode(signature.signedInfo.canonicalized) as Uint8List,
        base64.decode(signature.signatureValue)));
  }

  bool validateDigests(SamlResponse response) {
    var digest = SHA256Digest();

    for (var signature in response.signatures) {
      for (var reference in signature.signedInfo.references) {
        if (reference.digestMethodAlgorithm !=
            'http://www.w3.org/2001/04/xmlenc#sha256') {
          return false;
        }

        var element = reference.referenceElement;
        var elementToSign = element.copy();

        var prefix = element.name.prefix;

        if (prefix == null && element.name.namespaceUri != null) {
          elementToSign.setAttribute('xmlns', element.name.namespaceUri);
        } else {
          if (null == elementToSign.getAttribute('xmlns:$prefix')) {
            elementToSign.setAttribute(
                'xmlns:$prefix', element.name.namespaceUri);
          }
        }

        // remove signature element from object to sign
        var signatureToRemoves = elementToSign
            .findAllElements('Signature', namespace: Saml.XMLDSIG_NS)
            .map((e) => Signature(e))
            .where(
                (sig) => sig.signedInfo.references.first.uri == reference.uri)
            .map((e) => e.signatureElement)
            .toList();

        for (var signatureElement in signatureToRemoves) {
          signatureElement.parent!.children.remove(signatureElement);
        }

        var canon = XmlExcC14nWriter.canonicalized(elementToSign);

        if (reference.digestValue !=
            base64.encode(digest.process(utf8.encode(canon) as Uint8List))) {
          return false;
        }
      }
    }

    return true;
  }
}

class SamlLogoutRequest {
  late XmlElement _request;

  SamlLogoutRequest(String xml) {
    _request = XmlDocument.parse(xml).rootElement;
  }

  SamlLogoutRequest.fromIssuer(String issuer, String nameId) {
    var message = '''
<samlp:LogoutRequest 
xmlns="${Saml.SAML_METADATA_NS}" 
ID="${'id' + Uuid().v4()}" 
Version="2.0" 
IssueInstant="${DateTime.now().toUtc().toIso8601String()}" 
xmlns:samlp="${Saml.SAML_PROTOCOL_NS}">
  <Issuer xmlns="${Saml.SAML_ASSERTION_NS}">${issuer}</Issuer>
  <NameID xmlns="${Saml.SAML_ASSERTION_NS}">${nameId}</NameID>
</samlp:LogoutRequest>
''';
    _request = XmlDocument.parse(message).rootElement;
  }

  String? get id => _request.getAttribute('ID');
  String get issuer => _request.findElements('Issuer').first.text;
  String get nameId => _request.findElements('NameID').first.text;
  DateTime get issueInstant =>
      DateTime.parse(_request.getAttribute('IssueInstant')!);

  String toXml() => _request.toXmlString();
}

class SamlAuthnRequest {
  late XmlElement _request;

  SamlAuthnRequest(String xml) {
    _request = XmlDocument.parse(xml).rootElement;
  }

  SamlAuthnRequest.fromIssuer(String issuer) {
    var message = '''
<samlp:AuthnRequest
xmlns="${Saml.SAML_METADATA_NS}"
ID="${'id' + Uuid().v4()}"
Version="2.0" 
IssueInstant="${DateTime.now().toUtc().toIso8601String()}"
xmlns:samlp="${Saml.SAML_PROTOCOL_NS}">
<Issuer xmlns="${Saml.SAML_ASSERTION_NS}">${issuer}</Issuer>
</samlp:AuthnRequest>
''';
    _request = XmlDocument.parse(message).rootElement;
  }

  String get id => _request.getAttribute('ID')!;
  String get issuer => _request.findElements('Issuer').first.text;
  DateTime get issueInstant =>
      DateTime.parse(_request.getAttribute('IssueInstant')!);

  String toXml() => _request.toXmlString();
}

class SamlResponse {
  late XmlElement _response;

  SamlResponse(String xmlResponse) {
    _response = XmlDocument.parse(xmlResponse)
        .findElements('Response', namespace: Saml.SAML_PROTOCOL_NS)
        .first;
  }

  String get id => _response.getAttribute('ID')!;

  String get issuer => _response
      .findElements('Issuer', namespace: Saml.SAML_ASSERTION_NS)
      .first
      .text;

  List<Signature> get signatures => _response
      .findAllElements('Signature', namespace: Saml.XMLDSIG_NS)
      .map((e) => Signature(e))
      .toList();

  Iterable<Assertion> get assertions => _response
      .findAllElements('Assertion', namespace: Saml.SAML_ASSERTION_NS)
      .map((e) => Assertion(e));
}

class Assertion {
  final XmlElement _assertion;

  Assertion(this._assertion);

  bool validate(String issuer, String audience, {bool validateTime: true}) {
    if (this.audience != audience) {
      return false;
    }

    if (this.issuer.text != issuer) {
      return false;
    }

    if (validateTime) {
      if (DateTime.now().toUtc().isBefore(notBefore)) {
        return false;
      }
      if (DateTime.now().toUtc().isAfter(notOnOrAfter)) {
        return false;
      }
    }

    return true;
  }

  XmlElement get conditions => _assertion
      .findElements('Conditions', namespace: Saml.SAML_ASSERTION_NS)
      .first;

  DateTime get notBefore =>
      DateTime.parse(conditions.getAttribute('NotBefore')!);
  DateTime get notOnOrAfter =>
      DateTime.parse(conditions.getAttribute('NotOnOrAfter')!);

  XmlElement get audienceRestriction => conditions
      .findElements('AudienceRestriction', namespace: Saml.SAML_ASSERTION_NS)
      .first;

  String get audience => audienceRestriction
      .findElements('Audience', namespace: Saml.SAML_ASSERTION_NS)
      .first
      .text;

  Subject get subject => Subject(_assertion
      .findElements('Subject', namespace: Saml.SAML_ASSERTION_NS)
      .first);

  XmlElement get issuer => _assertion
      .findElements('Issuer', namespace: Saml.SAML_ASSERTION_NS)
      .first;
}

class Subject {
  final XmlElement _subject;

  Subject(this._subject);

  String get nameId => _subject
      .findElements('NameID', namespace: Saml.SAML_ASSERTION_NS)
      .first
      .text;
}

class Signature {
  final XmlElement _signature;

  Signature(this._signature);

  XmlElement get signatureElement => _signature;

  SignedInfo get signedInfo => SignedInfo(
      _signature.findElements('SignedInfo', namespace: Saml.XMLDSIG_NS).first);

  String get signatureValue => _signature
      .findElements('SignatureValue', namespace: Saml.XMLDSIG_NS)
      .first
      .text;
}

class SignedInfo {
  final XmlElement _signedInfo;

  SignedInfo(this._signedInfo);

  XmlElement get _canonicalizationMethod => _signedInfo
      .findElements('CanonicalizationMethod', namespace: Saml.XMLDSIG_NS)
      .first;

  String get canonicalizationMethodAlgorithm =>
      _canonicalizationMethod.getAttribute('Algorithm')!;

  XmlElement get _signatureMethod => _signedInfo
      .findElements('SignatureMethod', namespace: Saml.XMLDSIG_NS)
      .first;

  String get signatureMethodAlgorithm =>
      _signatureMethod.getAttribute('Algorithm')!;

  Iterable<Reference> get references => _signedInfo
      .findElements('Reference', namespace: Saml.XMLDSIG_NS)
      .map((e) => Reference(e));

  String get canonicalized {
    var buffer = StringBuffer();
    var writer = XmlExcC14nWriter(buffer);
    var si = _signedInfo.copy();

    var prefix = _signedInfo.name.prefix;

    if (prefix == null) {
      si.setAttribute('xmlns', _signedInfo.name.namespaceUri);
    } else {
      if (null == _signedInfo.getAttribute('xmlns:$prefix')) {
        si.setAttribute('xmlns:$prefix', _signedInfo.name.namespaceUri);
      }
    }

    writer.visit(si);
    return buffer.toString();
  }
}

class Reference {
  final XmlElement _reference;

  Reference(this._reference);

  String get digestValue => _reference
      .findElements('DigestValue', namespace: Saml.XMLDSIG_NS)
      .first
      .text;

  String get digestMethodAlgorithm => _reference
      .findElements('DigestMethod', namespace: Saml.XMLDSIG_NS)
      .first
      .getAttribute('Algorithm')!;

  String get uri => _reference.getAttribute('URI')!;

  XmlElement get referenceElement {
    if (null == uri) {
      return _reference.root as XmlElement;
    }

    return _reference.root
        .findAllElements('*')
        .where((element) => element.getAttribute('ID') != null)
        .firstWhere((e) => '#${e.getAttribute('ID')}' == uri);
  }
}

class Transforms {
  final XmlElement _transforms;

  Transforms(this._transforms);

  Iterable<Transform> get transforms => _transforms
      .findElements('Transform', namespace: Saml.XMLDSIG_NS)
      .map((e) => Transform(e));
}

class Transform {
  final XmlElement _transform;

  Transform(this._transform);

  String get algorithm => _transform.getAttribute('Algorithm')!;
}

class XmlExcC14nWriter with XmlVisitor {
  final StringSink buffer;
  final XmlEntityMapping entityMapping;

  static bool hasNamespaceDeclaration(XmlElement e, String? prefix) {
    if (prefix == null) {
      if (e.attributes.any((p0) => p0.name.local == 'xmlns')) {
        return true;
      }
      var parent = e.parent;
      if (parent == null) {
        return false;
      }
      if (parent.attributes.any((p0) => p0.name.local == 'xmlns')) {
        return true;
      }
      return hasNamespaceDeclaration(parent as XmlElement, prefix);
    } else {
      if (e.attributes
          .any((p0) => p0.name.prefix == 'xmlns' && p0.name.local == prefix)) {
        return true;
      }
      var parent = e.parent;
      if (parent == null) {
        return false;
      }
      if (parent.attributes
          .any((p0) => p0.name.prefix == 'xmlns' && p0.name.local == prefix)) {
        return true;
      }
      return hasNamespaceDeclaration(parent as XmlElement, prefix);
    }
  }

  // see tool
  // xsec-c14n -x -n test/responseWithSig.xml
  static String canonicalized(XmlElement element) {
    var copy = element.copy();

    var namespaceList = <String, String>{};

    var elements = [copy]..addAll(copy.findAllElements('*'));

    // collect namespaces
    elements.forEach((element) {
      element.attributes
          .where((p0) => p0.name.prefix == 'xmlns' || p0.name.local == 'xmlns')
          .forEach((p1) {
        namespaceList[p1.name.local] = p1.value;
      });
    });

    // remove namespaces
    elements.forEach((element) {
      element.attributes
          .where((a) => a.name.prefix == 'xmlns' || a.name.local == 'xmlns')
          .where((a) =>
              a.name.prefix != element.name.prefix || a.name.local == 'xmlns')
          .toList()
          .forEach((e) {
        element.attributes.remove(e);
      });
    });

    // add namespaces
    elements.forEach((element) {
      if (!hasNamespaceDeclaration(element, element.name.prefix)) {
        if (element.name.prefix == null) {
          element.attributes.insert(
              0, XmlAttribute(XmlName('xmlns'), namespaceList['xmlns']!));
        } else {
          element.attributes.insert(
              0,
              XmlAttribute(XmlName(element.name.prefix!, 'xmlns'),
                  namespaceList[element.name.prefix!]!));
        }
      }

      element.attributes
          .where((p0) => p0.name.prefix != null)
          .where((p0) => p0.name.prefix != 'xmlns')
          .toList()
          .forEach((p0) {
        if (!hasNamespaceDeclaration(element, p0.name.prefix)) {
          element.attributes.insert(
              0,
              XmlAttribute(XmlName(p0.name.prefix!, 'xmlns'),
                  namespaceList[p0.name.prefix!]!));
        }
      });
    });

    var buffer = StringBuffer();
    var writer = XmlExcC14nWriter(buffer);
    writer.visit(copy);

    return buffer.toString();
  }

  XmlExcC14nWriter(this.buffer, {XmlEntityMapping? entityMapping})
      : entityMapping = entityMapping ?? defaultEntityMapping;

  @override
  void visitAttribute(XmlAttribute node) {
    visit(node.name);
    buffer.write(XmlToken.equals);
    buffer.write(entityMapping.encodeAttributeValueWithQuotes(
        node.value, node.attributeType));
  }

  @override
  void visitCDATA(XmlCDATA node) {
    buffer.write(XmlToken.openCDATA);
    buffer.write(node.text);
    buffer.write(XmlToken.closeCDATA);
  }

  @override
  void visitComment(XmlComment node) {
    // buffer.write(XmlToken.openComment);
    // buffer.write(node.text);
    // buffer.write(XmlToken.closeComment);
  }

  @override
  void visitDeclaration(XmlDeclaration node) {
    buffer.write(XmlToken.openDeclaration);
    writeAttributes(node);
    buffer.write(XmlToken.closeDeclaration);
  }

  @override
  void visitDoctype(XmlDoctype node) {
    buffer.write(XmlToken.openDoctype);
    buffer.write(XmlToken.whitespace);
    buffer.write(node.text);
    buffer.write(XmlToken.closeDoctype);
  }

  @override
  void visitDocument(XmlDocument node) {
    writeIterable(node.children);
  }

  @override
  void visitDocumentFragment(XmlDocumentFragment node) {
    buffer.write('#document-fragment');
  }

  @override
  void visitElement(XmlElement node) {
    buffer.write(XmlToken.openElement);
    visit(node.name);
    writeAttributes(node);
    buffer.write(XmlToken.closeElement);
    writeIterable(node.children);
    buffer.write(XmlToken.openEndElement);
    visit(node.name);
    buffer.write(XmlToken.closeElement);
  }

  @override
  void visitName(XmlName name) {
    buffer.write(name.qualified);
  }

  @override
  void visitProcessing(XmlProcessing node) {
    buffer.write(XmlToken.openProcessing);
    buffer.write(node.target);
    if (node.text.isNotEmpty) {
      buffer.write(XmlToken.whitespace);
      buffer.write(node.text);
    }
    buffer.write(XmlToken.closeProcessing);
  }

  @override
  void visitText(XmlText node) {
    buffer.write(entityMapping.encodeText(node.text));
  }

  void writeAttributes(XmlHasAttributes node) {
    if (node.attributes.isNotEmpty) {
      buffer.write(XmlToken.whitespace);

      var attributes = node.attributes.toList();

      var attrs = attributes
          .where((element) => element.name.prefix == "xmlns" || element.localName == "xmlns")
          .toList();

      var others = attributes
          .where((element) => !(element.name.prefix == "xmlns" || element.localName == "xmlns"))
          .toList();

      others.sort((a, b) => a.localName.compareTo(b.localName));

      attrs.addAll(others);

      writeIterable(attrs, XmlToken.whitespace);
    }
  }

  void writeIterable(Iterable<XmlHasVisitor> nodes, [String? separator]) {
    final iterator = nodes.iterator;
    if (iterator.moveNext()) {
      if (separator == null || separator.isEmpty) {
        do {
          visit(iterator.current);
        } while (iterator.moveNext());
      } else {
        visit(iterator.current);
        while (iterator.moveNext()) {
          buffer.write(separator);
          visit(iterator.current);
        }
      }
    }
  }
}
