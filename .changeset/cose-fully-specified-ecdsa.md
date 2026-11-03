---
"@owf/cose": minor
"@owf/mdoc": patch
---

Support the fully-specified COSE ECDSA algorithms of RFC 9864 § 2.1: `SignatureAlgorithm.ESP256` (-9), `ESP384` (-51) and `ESP512` (-52). `Sign1.algorithm` accepts them, and `coseKeyToJwkClaim.algorithm` and `Sign1.jwaAlgorithm` convert them to the JWA `ES256`, `ES384` and `ES512`. `jwkToCoseKey.alg('ES256')` still returns `ES256` (-7). `Sign1.sign` and `Sign1.verifySignature` throw `CoseInvalidAlgorithmError` when the key is not an EC key on the curve the algorithm requires.

In `@owf/mdoc`, issuer auth, device auth, reader auth, `verifyStatusListToken` and `verifyIdentifierListToken` accept these algorithms. Device auth now verifies through `Sign1.verifySignature`, so the `sign1.verify` callback receives the `alg` of the device signature.
