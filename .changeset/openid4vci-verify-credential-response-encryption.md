---
"@openid4vc/openid4vci": minor
---

BREAKING: `parseCredentialRequest` now checks the `credential_response_encryption` of the request against the `credential_response_encryption` of the issuer metadata, and rejects it with `invalid_encryption_parameters` when encryption is required but missing, when the issuer does not advertise encryption, or when the `alg`, `enc` or `zip` value is not supported. Issuers that encrypt credential responses must advertise `credential_response_encryption` in their metadata. `parseDeferredCredentialRequest` (and `Openid4vciIssuer.parseDeferredCredentialRequest`) now requires `issuerMetadata` and performs the same check. The check is also exported as `verifyCredentialResponseEncryption`, and the issuer metadata schema accepts `zip_values_supported`.
