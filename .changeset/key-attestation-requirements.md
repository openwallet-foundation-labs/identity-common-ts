---
"@openid4vc/openid4vci": patch
---

Verify that a key attestation meets the `key_attestations_required` (`key_storage` and `user_authentication`) from the credential issuer metadata. Pass `keyAttestationsRequired` to the jwt and attestation proof verification (also on `Openid4vciIssuer`), or call `verifyKeyAttestationRequirements` directly.
