---
"@openid4vc/openid4vci": minor
---

`verifyCredentialRequestJwtProof` and `verifyCredentialRequestAttestationProof`, and the same methods on `Openid4vciIssuer`, accept a `credentialConfiguration` and verify the proof against it (OpenID4VCI 1.0 Section 12.2.4): the proof type must be in `proof_types_supported`, the proof `alg` in its `proof_signing_alg_values_supported` (Appendix F.1), and the proof key binding method in `cryptographic_binding_methods_supported` (a `jwk` key matches `jwk` or `cose_key`, a DID matches `did` or `did:<method>`). `key_attestations_required` of the proof type is used when `keyAttestationsRequired` is not passed. A check is skipped when its field is absent from the credential configuration.
