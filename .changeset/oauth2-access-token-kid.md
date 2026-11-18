---
'@openid4vc/oauth2': minor
---

The `signer` of `createAccessTokenJwt` and `Oauth2AuthorizationServer.createAccessTokenResponse` is now a `custom` signer, and the access token header gets its `kid` instead of a `jwk`. A resource server must verify an access token with the keys of the authorization server (RFC 9068 Section 4). It selects the key from the `jwks_uri` by `kid` (RFC 7515 Section 4.1.4), or takes the only key when there is one. Set a `kid` when the `jwks_uri` has more than one key, as during a key rollover.

**Breaking:** pass `{ method: 'custom', alg, kid }` as the `signer`, with the `kid` of the key in the `jwks_uri`. Your `signJws` callback selects the private key by that `kid`. A resource server that took the key from the `jwk` header must use the `jwks_uri` instead.
