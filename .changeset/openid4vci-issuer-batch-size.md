---
'@openid4vc/openid4vci': minor
---

`Openid4vciIssuer.parseCredentialRequest` rejects a credential request whose `proofs` array is larger than the `batch_size` of the `batch_credential_issuance` in the credential issuer metadata, or that has more than one key proof when the metadata has no `batch_credential_issuance` (OpenID4VCI 1.0 Section 12.2.4), with an `invalid_credential_request` error. Before, only the client checked this. The credential issuer metadata schema now also requires `batch_size` to be an integer of 2 or greater, as the same section says.

**Breaking:** an issuer that accepts more than one key proof per credential request must advertise it with `batch_credential_issuance.batch_size` in its credential issuer metadata, set to the largest number of proofs it accepts. Credential issuer metadata with a `batch_size` that is not an integer of 2 or greater no longer parses.
