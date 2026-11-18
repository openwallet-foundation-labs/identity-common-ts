# @owf/jose

## 0.8.0

### Minor Changes

- f6d2c57: Add `signFlattenedJws` and `signGeneralJws` to sign the JSON serializations of a JWS.
- 5d665bb: Add `@owf/jose`: JOSE (JWK, JWA, JWS, JWT and JWE) with strict, schema based parsing and verification. A token type is described with zod schemas, with which `decodeJwt`, `signJwt` and `verifyJwt` validate and type its header and claims. Signing and verification go through `SignJwsCallback` and `VerifyJwsCallback` callbacks that sign or verify the exact bytes the package computed, and encrypting or decrypting a JWE is left to the caller.
- 946d9af: BREAKING: `signCompactJws` and `signJwt` reject a header whose `kid`, `x5c`, `jwk` or `trust_chain` contradicts the signer, or that also identifies a signer of another method, such as a `jwk` next to the `x5c` of an `x5c` signer. `jwsSignerFromHeader` would establish another signer from such a header. A header that leaves the signer's parameters out is still signed.

### Patch Changes

- Updated dependencies [0f663bf]
- Updated dependencies [ebd0b4b]
- Updated dependencies [21cd668]
- Updated dependencies [ec2ed51]
- Updated dependencies [ec2ed51]
- Updated dependencies [cb487f1]
- Updated dependencies [5fff735]
- Updated dependencies [04cfd04]
  - @owf/identity-common@0.8.0
