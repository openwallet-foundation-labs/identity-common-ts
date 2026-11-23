---
'@openid4vc/openid4vci': patch
---

`Openid4vciIssuer.parseCredentialRequest` rejects a credential request whose `proofs` array is larger than the `batch_size` of the `batch_credential_issuance` in the credential issuer metadata, or that has more than one key proof when the metadata has no `batch_credential_issuance` (OpenID4VCI 1.0 Section 12.2.4), with an `invalid_credential_request` error. Before, only the client checked this.
