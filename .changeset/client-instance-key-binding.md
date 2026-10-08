---
'@openid4vc/oauth2': minor
---

Bind authorization sessions and refresh tokens to the client instance key. `verifyClientAttestationJwt` now returns `confirmationJwkThumbprint`, the thumbprint of the `cnf` key of the client attestation, and accepts `expectedConfirmationJwkThumbprint` and `expectedClientId` to reject a client attestation for another key or client id. Authorization requests, token requests and `Oauth2AuthorizationServer.verifyClientAttestation` accept the same options. Pass `clientAttestation.clientAttestation.confirmationJwkThumbprint` from an earlier request as `clientAttestation.expectedConfirmationJwkThumbprint` in later requests, as required for refresh tokens by draft-ietf-oauth-attestation-based-client-auth section 10.3. A client attestation is required when it is set.

`verifyClientAttestationJwt` now requires the `hash` callback.
