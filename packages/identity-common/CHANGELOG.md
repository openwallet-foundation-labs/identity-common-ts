# @owf/identity-common

## 0.3.2

## 0.3.1

## 0.3.0

### Patch Changes

- 353df0c: feat: add hex parser

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

## 0.1.0

### Minor Changes

- 7ef6497: Migrate reusable packages from sd-jwt-js

  - **@owf/identity-common**: Add shared types (JwtPayload, Signer, Verifier, Hasher, etc.), base64url utilities, and JWT decoding
  - **@owf/crypto**: Add Web Crypto API wrappers (ES256/384/512 key generation, signing, verification) and SHA-256/384/512 hash functions
  - **@owf/token-status-list**: Add core StatusList class with bitstring compression/decompression (1/2/4/8-bit), JWT transport layer, and CWT/CBOR transport layer for Token Status Lists (draft-ietf-oauth-status-list)

### Patch Changes

- f50ec6e: add lote package

  add package-specific exception classes (`CryptoException`, `LoTEException`, `IdentityCommonException`) extending a shared `IdentityException` base class in `@owf/identity-common`, replacing plain `Error` throws across all packages. Refactor `SLException` to also extend `IdentityException`.
