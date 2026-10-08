---
'@openid4vc/oauth2': minor
'@openid4vc/openid4vci': minor
'@openid4vc/openid4vp': minor
---

BREAKING: the JWT handling is built on `@owf/jose`, and `@openid4vc/oauth2` no longer exports its JWK, JWA, JWS and JWT helpers. Import them from `@owf/jose`:

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

BREAKING: the `signJwt` and `verifyJwt` callbacks of the `CallbackContext` are replaced by `signJws` and `verifyJws`, and the `SignJwtCallback` and `VerifyJwtCallback` types by `SignJwsCallback` and `VerifyJwsCallback`. They sign or verify the signing input the library computed rather than a whole JWT, and report the public key they used, for example `signJws: async (signer, { signingInputBytes }) => ({ signature, signerJwk })` with the signature base64url encoded. A callback can therefore no longer add header parameters.

BREAKING: `verifyJwt` of `@owf/jose` takes the compact JWT or the result of `decodeJwt` as `jwt`, instead of `compact`, `header` and `payload`, and `verifyJwsCallback` instead of `verifyJwtCallback`. `allowedSkewInSeconds` is `skewSeconds`, and `skipTimeBasedValidation` is replaced by `checkExpirationTime`, `checkNotBefore` and `checkIssuedAt`.

JWTs are verified more strictly:

- Claims are verified with a default clock skew of 30 seconds instead of 0, a token issued in the future is rejected, and a token is rejected at exactly its `exp`. This changes the default `allowedSkewInSeconds` of client attestation verification from 0 to 30 seconds.
- An `expectedAudience` rejects a token without `aud`.
- `none` in any casing, a registered algorithm in another casing such as `hs256`, and the symmetric `HS256`, `HS384` and `HS512` are rejected, and the key that verified the signature must fit the algorithm.
- A header that identifies the signer in more than one way, such as `x5c` next to `jwk`, is rejected, and a DID in `kid` must be exactly the DID in `iss`.
- `verifyJwtProfileAccessToken` and `verifyIdTokenJwt` no longer fall back to the only key of the JWKS when the `kid` of the token is not in it.
- A header or payload in standard base64, with padding or with invalid UTF-8, an empty signature, an invalid registered claim, a `jwk` or `cnf.jwk` with private key material, and a `crit` parameter that is not understood are rejected.

A token signed with a `custom` signer that has a `kid` now carries that `kid` in its header.
