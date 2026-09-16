---
'@owf/identity-common': minor
'@sd-jwt/core': patch
---

Add `base64urlDecodeJson` to `@owf/identity-common`, and use it in `decodeJwt`. Bytes that are not valid UTF-8 are now rejected instead of being decoded to a different string, and invalid base64url, UTF-8 or JSON in a JWT header or payload all throw `IdentityCommonException('Invalid JWT as input')`, without exposing parser details.

`@sd-jwt/core` now uses these functions from `@owf/identity-common` for decoding JWTs and disclosures, instead of its own implementation. Errors are still thrown as `SDJWTException` with the same messages.
