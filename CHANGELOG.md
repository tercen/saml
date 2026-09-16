## 1.1.6

- `Saml.fromCertificatePem`: accept the IdP signing certificate as an inline
  string — PEM-armoured or bare base64 DER (the form IdP federation metadata
  publishes inside `X509Certificate` elements) — for deployments where a
  certificate file cannot be delivered to the process (sci key
  `tercen.saml.certificate`, tercen/sci#1602 companion (a)).

## 1.0.0

- Initial version.
