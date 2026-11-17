---
'@openid4vc/oauth2': minor
---

`verifyResourceRequest`, `Oauth2ResourceServer.verifyResourceRequest` and `verifyJwtProfileAccessToken` accept authorization servers as issuer identifier as well as metadata, and resolve an identifier only when needed, with the `getAuthorizationServerMetadata` callback or else over HTTP. For a JWT access token only the listed authorization server of its `iss` is resolved. For an opaque access token they are resolved one at a time, until one reports the token as active through introspection. Before, the caller had to fetch the metadata of every authorization server for each request.

The `getJwks` callback gets the `kid` of the JWT it is called for, as `getJwks(jwksUri, { kid })`, for access tokens and ID tokens. A callback that caches JWK Sets can fetch one again when it lacks that key, to pick up a rotated key. `fetchJwks` takes the `kid` as a third argument.
