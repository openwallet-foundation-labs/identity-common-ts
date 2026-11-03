---
"@owf/cose": minor
"@owf/mdoc": patch
---

Support the fully-specified COSE signature algorithms of RFC 9864: `SignatureAlgorithm.ESP256` (-9), `ESP384` (-51) and `ESP512` (-52) from § 2.1, and `Ed25519` (-19) and `Ed448` (-53) from § 2.2. `Sign1.algorithm` accepts them. `coseKeyToJwkClaim.algorithm` and `Sign1.jwaAlgorithm` convert ESP256, ESP384 and ESP512 to the JWA `ES256`, `ES384` and `ES512`, and Ed25519 and Ed448 to the JWA names of the same name. `jwkToCoseKey.alg('ES256')` still returns `ES256` (-7), and `jwkToCoseKey.alg('Ed25519')` returns -19.

`Sign1.sign` and `Sign1.verifySignature` throw `CoseInvalidAlgorithmError` when the key type or curve of the key does not match the algorithm (RFC 9053 § 2.1 and § 2.2, RFC 9864 § 2.1 and § 2.2). ES256, ES384 and ES512 require an EC2 key on P-256, P-384 or P-521, and EdDSA an OKP key on Ed25519 or Ed448. The fully-specified algorithms require the one curve they are defined for. The `alg` of the key is not compared, and RSA algorithms are not checked.

In `@owf/mdoc`, issuer auth, device auth, reader auth, `verifyStatusListToken` and `verifyIdentifierListToken` accept these algorithms. Device auth now verifies through `Sign1.verifySignature`, so the `sign1.verify` callback receives the `alg` of the device signature, and the key check applies to it.
