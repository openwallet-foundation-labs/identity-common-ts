---
'@openid4vc/oauth2': minor
'@openid4vc/openid4vci': minor
---

Less repeated decoding, hashing and validation within one flow. Nothing changes on the wire.

- `createAccessTokenJwt` and `Oauth2AuthorizationServer.createAccessTokenResponse` accept `dpop.jwkThumbprint`, the value `verifyAccessTokenRequest` already returns, and use it instead of calculating the thumbprint again.
- The `dpop` result of the `verify*AccessTokenRequest` methods has the `header` and `payload` of the DPoP proof. The `dpop` result of `verifyResourceRequest` has `jwkThumbprint`, `header` and `payload`. The result of `Oauth2AuthorizationServer.verifyDpopJwt` has `jwk`.
- `verifyResourceRequest` decodes a JWT access token once instead of twice.
- `resourceRequest` hashes the access token once when it retries with a DPoP nonce. `createDpopHeadersForRequest` accepts an `accessTokenHash`.
- `createAuthorizationRequestUrl`, `sendAuthorizationChallengeRequest` and `Oauth2Client.initiateAuthorization` accept `pkce`, the result of `createPkce`. `initiateAuthorization` hashes the code verifier once.
- `clientAuthenticationClientAttestationJwt` and `clientAuthenticationClientAttestationJwtDpop` decode the client attestation once, not on every request, and not at all when a `signer` is passed.
- `createCredentialRequestJwtProof` accepts the result of `parseKeyAttestationJwt` as `keyAttestationJwt`. That result has the exported type `ParsedKeyAttestationJwt`.
- Credential issuer metadata: the schema of each credential format is built once, signed metadata is validated once, and credential configurations with an unknown format are skipped without validating them.
- `parseCredentialRequestPayload` no longer validates `proofs` a second time.
