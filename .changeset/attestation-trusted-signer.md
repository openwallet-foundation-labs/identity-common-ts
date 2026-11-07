---
'@openid4vc/oauth2': minor
'@openid4vc/openid4vci': minor
---

`verifyClientAttestationJwt` and `verifyKeyAttestationJwt` reject an attestation signed with a `jwk` or `did` signer. This also applies to `Oauth2AuthorizationServer.verifyClientAttestation`, the verification of authorization, pushed authorization and access token requests, `Openid4vciIssuer.verifyWalletAttestation`, and the issuer's verification of `jwt` and `attestation` proofs. The signer was taken from the attestation's own header, and `verifyJws` has to accept such keys for DPoP, PoP and proof JWTs, so a client could attest itself and a wallet could attest its own keys, for example to meet `key_attestations_required` (OpenID4VCI 1.0 Appendix D).

**Breaking:** the attester must be identified by `x5c`, a federation `trust_chain`, or a `kid` that `verifyJws` resolves, and `verifyJws` decides whether it trusts it, for example by validating the `x5c` chain. Sign attestations with one of these signers instead of a `jwk` header or a DID in `kid`.
