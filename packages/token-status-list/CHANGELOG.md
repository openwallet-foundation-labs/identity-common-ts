# @owf/token-status-list

## 0.3.1

### Patch Changes

- @owf/cose@0.3.1
- @owf/identity-common@0.3.1

## 0.3.0

### Minor Changes

- eff25c4: remove export from dependencies
- dad635c: refactor: only allow CoseKey as return value for getPublicKey in x509 context
- dad635c: refactor: only allow CosKey for sign1.verify

### Patch Changes

- 353df0c: feat: add status list info objects for referenced status list token
- 9451711: Add a way for a CWT status list to add additional claims
- 4928369: feat: make totalStatuses public readonly in StatusList class
- Updated dependencies [4bd7eb7]
- Updated dependencies [f1f42db]
- Updated dependencies [dad635c]
- Updated dependencies [6309c48]
- Updated dependencies [353df0c]
- Updated dependencies [dad635c]
- Updated dependencies [353df0c]
- Updated dependencies [353df0c]
- Updated dependencies [353df0c]
- Updated dependencies [2b0eeaf]
  - @owf/cose@0.3.0
  - @owf/identity-common@0.3.0

## 0.2.0

### Minor Changes

- 7ef6497: Migrate reusable packages from sd-jwt-js

  - **@owf/identity-common**: Add shared types (JwtPayload, Signer, Verifier, Hasher, etc.), base64url utilities, and JWT decoding
  - **@owf/crypto**: Add Web Crypto API wrappers (ES256/384/512 key generation, signing, verification) and SHA-256/384/512 hash functions
  - **@owf/token-status-list**: Add core StatusList class with bitstring compression/decompression (1/2/4/8-bit), JWT transport layer, and CWT/CBOR transport layer for Token Status Lists (draft-ietf-oauth-status-list)

### Patch Changes

- b79d4ba: align package json for export
- f50ec6e: add lote package

  add package-specific exception classes (`CryptoException`, `LoTEException`, `IdentityCommonException`) extending a shared `IdentityException` base class in `@owf/identity-common`, replacing plain `Error` throws across all packages. Refactor `SLException` to also extend `IdentityException`.

- 293e5ec: Also include commonjs builds
- Updated dependencies [b79d4ba]
- Updated dependencies [7ef6497]
- Updated dependencies [f50ec6e]
- Updated dependencies [293e5ec]
  - @owf/identity-common@0.2.0
  - @owf/cose@0.2.0

## 0.1.0

### Minor Changes

- 7ef6497: Migrate reusable packages from sd-jwt-js

  - **@owf/identity-common**: Add shared types (JwtPayload, Signer, Verifier, Hasher, etc.), base64url utilities, and JWT decoding
  - **@owf/crypto**: Add Web Crypto API wrappers (ES256/384/512 key generation, signing, verification) and SHA-256/384/512 hash functions
  - **@owf/token-status-list**: Add core StatusList class with bitstring compression/decompression (1/2/4/8-bit), JWT transport layer, and CWT/CBOR transport layer for Token Status Lists (draft-ietf-oauth-status-list)

### Patch Changes

- f50ec6e: add lote package

  add package-specific exception classes (`CryptoException`, `LoTEException`, `IdentityCommonException`) extending a shared `IdentityException` base class in `@owf/identity-common`, replacing plain `Error` throws across all packages. Refactor `SLException` to also extend `IdentityException`.

- Updated dependencies [7ef6497]
- Updated dependencies [f50ec6e]
  - @owf/identity-common@0.1.0
