---
"@openid4vc/oauth2": patch
---

Allow configuring clock skew for client attestation verification on the authorization server.

- Add optional `allowedSkewInSeconds` (default `0`) to the `clientAttestation` options of `verifyPushedAuthorizationRequest`, `verifyAuthorizationChallengeRequest` and the `verify*AccessTokenRequest` methods. It is applied to the `nbf` and `exp` checks of both the Client Attestation JWT and the Client Attestation PoP JWT, including the DPoP-bound `attest_jwt_client_auth_dpop` method.
- `verifyClientAttestationJwt` now honours its `allowedSkewInSeconds` option, which was previously ignored.
