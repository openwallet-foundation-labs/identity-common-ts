---
'@openid4vc/oauth2': patch
'@openid4vc/openid4vci': patch
---

Proofs of possession are only accepted for a limited time, so a captured one can no longer be replayed indefinitely:

- `verifyDpopJwt`, and the DPoP checks of `verifyAuthorizationRequest`, `verifyPushedAuthorizationRequest`, the access token request verification and `verifyResourceRequest`, reject a DPoP proof whose `iat` is more than 300 seconds ago unless `maxProofAgeSeconds` allows more (RFC 9449 Section 11.1). Before, a proof without `maxProofAgeSeconds` was valid forever. `expectedNonce` is now accepted by all of them, so a server can require its nonce for authorization and resource requests too (RFC 9449 Section 8).
- `verifyClientAttestationPopJwt` requires the `iat` of a client attestation PoP (draft-ietf-oauth-attestation-based-client-auth-09 Section 5.2) and rejects one older than 300 seconds. `verifyClientAttestation` and the client attestation options of the authorization and access token request verification accept `expectedChallenge`, so a server can enforce the challenge it issued (Section 6).
- `verifyCredentialRequestJwtProof` rejects a `jwt` proof whose `iat` is more than 300 seconds ago (OpenID4VCI 1.0 Appendix F.4).
