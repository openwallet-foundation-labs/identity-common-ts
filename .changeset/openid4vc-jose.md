---
'@openid4vc/oauth2': minor
'@openid4vc/openid4vci': minor
'@openid4vc/openid4vp': minor
---

**Breaking:** JWT handling is built on `@owf/jose`. `@openid4vc/oauth2` no longer exports its JWK, JWA, JWS and JWT helpers:

| Removed from `@openid4vc/oauth2` | Import from `@owf/jose` |
| --- | --- |
| `decodeJwt`, `decodeJwtHeader`, `verifyJwt`, `DecodeJwtOptions`, `DecodeJwtResult`, `Jwk`, `JwkSet`, `zJwk`, `zJwkSet`, `JwtHeader`, `JwtPayload`, `zJwtHeader`, `zJwtPayload`, `zCompactJwt`, `zCompactJwe`, `JweEncryptor`, `calculateJwkThumbprint`, `CalculateJwkThumbprintOptions` | the same names |
| `DecodeJwtHeaderResult` | `ReturnType<typeof decodeJwtHeader>` |
| `jwtHeaderFromJwtSigner` | `jwsHeaderFromSigner` |
| `jwtSignerFromJwt({ header, payload })` | `jwsSignerFromHeader({ header, issuer: payload.iss })` |
| `JwtSigner`, `JwtSignerCustom`, `JwtSignerDid`, `JwtSignerJwk`, `JwtSignerWithJwk`, `JwtSignerX5c` | `JwsSigner`, `JwsSignerCustom`, `JwsSignerDid`, `JwsSignerJwk`, `JwsSignerWithJwk`, `JwsSignerX5c` |
| `zAlgValueNotNone` | `zJwsAlg` |
| `jwaSignatureAlgorithmToFullySpecifiedCoseAlgorithm`, `fullySpecifiedCoseAlgorithmToJwaSignatureAlgorithm` | `jwaSignatureAlgorithmToCoseAlgorithm`, `coseAlgorithmToJwaSignatureAlgorithm` |
| `jwaSignatureAlgorithmArrayToFullySpecifiedCoseAlgorithmArray`, `fullySpecifiedCoseAlgorithmArrayToJwaSignatureAlgorithmArray` | `jwaSignatureAlgorithmsToCoseAlgorithms`, `coseAlgorithmsToJwaSignatureAlgorithms` |

**Breaking:** the `CallbackContext` callbacks `signJwt` and `verifyJwt` are replaced by `signJws` and `verifyJws` (`SignJwsCallback`, `VerifyJwsCallback`). They sign or verify the signing input and return the public key they used. `hash` is a `Hasher` of `@owf/identity-common` that gets the algorithm as `'sha-256'`. The `HashAlgorithm` enum and `HashCallback` type are removed.

**Breaking:** `verifyJwt` takes `jwt` (compact or decoded), `verifyJwsCallback` and `skewSeconds`. `checkExpirationTime`, `checkNotBefore` and `checkIssuedAt` replace `skipTimeBasedValidation`.

**Breaking:** JWTs are verified more strictly. The default skew is 30 seconds instead of 0, also for client attestations. A token issued in the future, a token at its `exp`, a missing `aud` when one is expected, `none`, `HS256`/`HS384`/`HS512` and miscased algorithms are rejected. A header must identify its signer in one way only, and a DID in `kid` must be the `iss`. The JWKS no longer falls back to its only key for an unknown `kid`. Parts that are not base64url, private keys in `jwk` or `cnf.jwk`, and a `crit` that is not understood are rejected.
