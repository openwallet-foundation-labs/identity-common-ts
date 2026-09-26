# @owf/eudi-jades

## 0.4.1

### Patch Changes

- @owf/crypto@0.4.1
  - @owf/identity-common@0.4.1

## 0.4.0

### Minor Changes

- a986752: Align the JAdES component schemas, signing-time transition, protected and unprotected header rules, detached payload
  handling, baseline profile checks, serializers, and verifiers with ETSI TS 119 182-1 V1.2.1. Add flattened JWS
  verification, package test/build conventions, and conformance coverage.
- c55b5d0: **Breaking:** stop reaching for `globalThis.crypto`. Hashing now comes from a caller-supplied,
  pluggable implementation, so consumers on runtimes without a global Web Crypto API — and consumers
  that must route crypto through a reviewed or policy-constrained engine — are no longer forced to
  patch the global.
  
  - `@owf/token-status-list`: `createStatusListIndexAllocator` and `StatusListIndexAllocator.create` take
    `(options, ctx)` instead of positional arguments, where `options` is `{ length, seed, position? }` and
    `ctx` is `{ hasher }`. The hasher must compute SHA-256 for the permutation to stay reproducible.
    Persisted allocator state can be passed straight through: `StatusListIndexAllocator.create(state, ctx)`.
  - `@owf/eudi-jades`: `Token.getHash` takes the hasher as its first argument —
    `getHash(hasher, algorithm?)`, e.g. `token.getHash(hasher)` with `hasher` from `@owf/crypto`.

### Patch Changes

- 65a7173: Build all base64, base64url, UTF-8 and JSON encoding on a single implementation in `@owf/identity-common`.
  
  - `base64` and `base64url` share one codec. Decoding input with an impossible length (a single trailing character) now throws instead of returning a corrupt byte.
  - `stringToBytes` and `bytesToString` use `TextEncoder` and `TextDecoder`, which must now be available in the environment (see the React Native notes in the README). `bytesToString` and `base64urlDecode` accept `{ fatal: true }` to throw on invalid UTF-8 instead of replacing it.
  - `base64urlDecodeJson` and `decodeJwt` build on these layers.
  
  `@owf/crypto`, `@owf/eudi-jades`, `@owf/eudi-sca` and `@owf/token-status-list` use these functions instead of their own `TextEncoder`, `TextDecoder` and `JSON.parse` calls. JSON decoded from base64url (JAdES headers and `etsiU` values, transaction data, and status list token payloads) is now strict about UTF-8.
- Updated dependencies [b7e7f15]
- Updated dependencies [5934a14]
- Updated dependencies [65a7173]
- Updated dependencies [65a7173]
  - @owf/identity-common@0.4.0
  - @owf/crypto@0.4.0
