import 'dart:io';
import 'dart:convert';
import 'dart:typed_data';

import 'package:xml/xml.dart';

import 'package:rsa_pkcs/rsa_pkcs.dart' as rsa;
import 'package:pointycastle/export.dart';

class Saml {
  static const String SAML_PROTOCOL_NS = 'urn:oasis:names:tc:SAML:2.0:protocol';
  static const String SAML_ASSERTION_NS =
      'urn:oasis:names:tc:SAML:2.0:assertion';
  static const String XMLDSIG_NS = 'http://www.w3.org/2000/09/xmldsig#';

  RSASigner _signer;

  final String _issuer;
  final String _audience;

  static Future<Saml> fromCertificatePemFile(
      String certificateFile, String issuer, String audience) async {
    final certFile = File(certificateFile);
    var rsaParser = rsa.RSAPKCSParser();
    final pair = rsaParser.parsePEM(await certFile.readAsString());
    var publicKey = RSAPublicKey(
        pair.public.modulus, BigInt.from(pair.public.publicExponent));
    final verifier = RSASigner(SHA256Digest(), '0609608648016503040201');
    verifier.init(false, PublicKeyParameter<RSAPublicKey>(publicKey)); // false=

    return Saml(issuer, audience, verifier); // verify
  }

  Saml(this._issuer, this._audience, this._signer) {}

  bool _rsaVerify(Uint8List signedData, Uint8List signature) {
    final sig = RSASignature(signature);

    try {
      return _signer.verifySignature(signedData, sig);
    } on ArgumentError {
      return false; // for Pointy Castle 1.0.2 when signature has been modified
    }
  }

  String get issuer => _issuer;
  String get audience => _audience;

  bool validateResponse(SamlResponse response, {bool validateTime: true}) {
    if (response.issuer != _issuer) {
      return false;
    }

    for (var assertion in response.assertions) {
      if (!assertion.validate(issuer, audience, validateTime: validateTime)) {
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
    return _rsaVerify(utf8.encode(response.signature.signedInfo.canonicalized),
        base64.decode(response.signature.signatureValue));
  }

  bool validateDigests(SamlResponse response) {
    var digest = SHA256Digest();

    for (var reference in response.signature.signedInfo.references) {
      if (reference.digestMethodAlgorithm !=
          'http://www.w3.org/2001/04/xmlenc#sha256') {
        return false;
      }

      // if (reference.uri != response.id) {
      //   return false;
      // }

      var canon = response.canonicalizedWithoutSignature;

      if (reference.digestValue !=
          base64.encode(digest.process(utf8.encode(canon)))) {
        return false;
      }
    }

    return true;
  }
}

class SamlResponse {
  XmlElement _response;

  SamlResponse(String xmlResponse) {
    _response = XmlDocument.parse(xmlResponse)
        .findElements('Response', namespace: Saml.SAML_PROTOCOL_NS)
        .first;
  }

  String get canonicalizedWithoutSignature {
    var res = _response.copy();

    res.children.remove(
        res.findElements('Signature', namespace: Saml.XMLDSIG_NS).first);

    return XmlExcC14nWriter.canonicalized(res);
  }

  String get id => _response.getAttribute('ID');

  String get issuer => _response
      .findElements('Issuer', namespace: Saml.SAML_ASSERTION_NS)
      .first
      .text;

  Signature get signature => Signature(
      _response.findElements('Signature', namespace: Saml.XMLDSIG_NS).first);

  Iterable<Assertion> get assertions => _response
      .findElements('Assertion', namespace: Saml.SAML_ASSERTION_NS)
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
      if (notBefore.isBefore(DateTime.now())) {
        return false;
      }
      if (notOnOrAfter.isAfter(DateTime.now())) {
        return false;
      }
    }

    return true;
  }

  XmlElement get conditions => _assertion
      .findElements('Conditions', namespace: Saml.SAML_ASSERTION_NS)
      .first;

  DateTime get notBefore =>
      DateTime.parse(conditions.getAttribute('NotBefore'));
  DateTime get notOnOrAfter =>
      DateTime.parse(conditions.getAttribute('NotOnOrAfter'));

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
      _canonicalizationMethod.getAttribute('Algorithm');

  XmlElement get _signatureMethod => _signedInfo
      .findElements('SignatureMethod', namespace: Saml.XMLDSIG_NS)
      .first;

  String get signatureMethodAlgorithm =>
      _signatureMethod.getAttribute('Algorithm');

  Iterable<Reference> get references => _signedInfo
      .findElements('Reference', namespace: Saml.XMLDSIG_NS)
      .map((e) => Reference(e));

  String get canonicalized {
    var buffer = StringBuffer();
    var writer = XmlExcC14nWriter(buffer);
    var si = _signedInfo.copy();

    var prefix = _signedInfo.name.prefix;

    if (null == _signedInfo.getAttribute('xmlns:$prefix')) {
      si.setAttribute('xmlns:$prefix', _signedInfo.name.namespaceUri);
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
      .getAttribute('Algorithm');

  String get uri => _reference.getAttribute('URI');
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

  String get algorithm => _transform.getAttribute('Algorithm');
}

class XmlExcC14nWriter with XmlVisitor {
  final StringSink buffer;
  final XmlEntityMapping entityMapping;

  static bool hasNamespaceDeclaration(XmlElement e, String prefix) {
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
    return hasNamespaceDeclaration(parent, prefix);
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
          .where((p0) => p0.name.prefix == 'xmlns' || p0.name.local == 'xmlns')
          .where((e) => e.name.prefix != element.name.prefix)
          .toList()
          .forEach((e) {
        element.attributes.remove(e);
      });
    });

    // add namespaces
    elements.forEach((element) {
      if (!hasNamespaceDeclaration(element, element.name.prefix)) {
        element.attributes.insert(
            0,
            XmlAttribute(XmlName(element.name.prefix, 'xmlns'),
                namespaceList[element.name.prefix]));
      }

      element.attributes
          .where((p0) => p0.name.prefix != null)
          .where((p0) => p0.name.prefix != 'xmlns')
          .toList()
          .forEach((p0) {
        if (!hasNamespaceDeclaration(element, p0.name.prefix)) {
          element.attributes.insert(
              0,
              XmlAttribute(XmlName(p0.name.prefix, 'xmlns'),
                  namespaceList[p0.name.prefix]));
        }
      });
    });

    var buffer = StringBuffer();
    var writer = XmlExcC14nWriter(buffer);
    writer.visit(copy);

    return buffer.toString();
  }

  XmlExcC14nWriter(this.buffer, {XmlEntityMapping entityMapping})
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
      writeIterable(node.attributes, XmlToken.whitespace);
    }
  }

  void writeIterable(Iterable<XmlHasVisitor> nodes, [String separator]) {
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
