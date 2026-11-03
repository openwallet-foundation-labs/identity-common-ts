---
'@owf/jose': minor
---

Add `@owf/jose`: JOSE (JWK, JWA, JWS, JWT and JWE) with strict, schema based parsing and verification. A token type is described with zod schemas, with which `decodeJwt`, `signJwt` and `verifyJwt` validate and type its header and claims. Signing and verification go through `SignJwsCallback` and `VerifyJwsCallback` callbacks that sign or verify the exact bytes the package computed, and encrypting or decrypting a JWE is left to the caller.
