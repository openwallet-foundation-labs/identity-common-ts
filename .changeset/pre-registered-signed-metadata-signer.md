---
'@openid4vc/openid4vp': minor
'@openid4vc/openid4vci': minor
---

`resolveOpenid4vpAuthorizationRequest` and `verifyJarRequest` reject the request object of a `pre-registered` client when it is signed with a `jwk` or `did` signer, and `Openid4vpAuthorizationRequestError` reports a `pre-registered` client as not authenticated (`isClientAuthenticated` is `false`, `client` is `undefined`). The keys and the `response_uri` of a pre-registered client are registered with the wallet (OpenID4VP 1.0 Section 5.9), which the library cannot check: anyone could sign a request for any `client_id` with a key of their own, and the client was reported as authenticated. For the same reason, `fetchCredentialIssuerMetadata` and `Openid4vciClient.resolveIssuerMetadata` reject signed credential issuer metadata that is signed with a `jwk` or `did` signer (OpenID4VCI 1.0 Section 12.2.3).

**Breaking:** sign the request objects of pre-registered clients with a `kid` that `verifyJws` resolves to a registered key, or with `x5c`. Sign credential issuer metadata with a `kid`, `x5c` or a federation `trust_chain`. Check the registration of a pre-registered client yourself before sending it an error response.
