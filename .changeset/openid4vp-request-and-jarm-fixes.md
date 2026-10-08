---
'@openid4vc/openid4vp': patch
---

Fixes for authorization requests and JARM responses:

- Verifying an encrypted JAR request object no longer fails before it is decrypted.
- `createOpenid4vpAuthorizationRequest` uses its `now` option for the `iat` and `exp` of the request object.
- `jarm.expiresInSeconds` of `createOpenid4vpAuthorizationResponse` sets the lifetime of a signed JARM response, 10 minutes by default, where it was used as its absolute `exp`.
- A response is no longer encrypted to a key with `use: 'sig'`, unless the `kid` names it.
- `verifyJarmAuthorizationResponse` accepts a signed response whose header identifies the key with `jwk` or `x5c` instead of `kid`, and verifies the `exp`, `nbf` and `iat` of a response with a clock skew of 30 seconds, where only `exp` was checked.
- When the signature of a signed response does not verify, the `@owf/jose` error is kept as `cause`, and the `error_description` says whether the algorithm, the signer or the signature was rejected.
- Response parameters that do not validate raise a `JoseValidationError` or `ValidationError` instead of a `ZodError`.
