## 1.1.8

- SECURITY: removed a leftover debug `print` in the exc-c14n
  canonicalization helper that dumped the full canonicalized Assertion —
  NameID (user email) + attributes — to stdout on EVERY signature
  validation (PII in pod logs; present since 1.1.4).
## 1.1.7

- `SamlMetadata.parse` + `Saml.fromMetadata`: build a Saml from an IdP
  metadata (EntityDescriptor) document — entityID becomes the IdP issuer,
  the HTTP-Redirect `SingleSignOnService` location the binding URL, and
  EVERY advertised signing certificate becomes a verification key. URL
  fetching is left to the caller (sci key `tercen.saml.metadata.url` /
  `tercen.saml.metadata`, tercen/sci#1602).
- Multi-key verification: a response signature now validates against ANY
  advertised key, turning IdP certificate rollover into a non-event.
## 1.1.6

- `Saml.fromCertificatePem`: accept the IdP signing certificate as an inline
  string — PEM-armoured or bare base64 DER (the form IdP federation metadata
  publishes inside `X509Certificate` elements) — for deployments where a
  certificate file cannot be delivered to the process (sci key
  `tercen.saml.certificate`, tercen/sci#1602 companion (a)).

## 1.0.0

- Initial version.
