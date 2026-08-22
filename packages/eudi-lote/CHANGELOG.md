# @owf/eudi-lote

## 0.3.2

### Patch Changes

- d87e13b: Simplifies the errors returned by `validateLoTEProfile` by pre-matching the given LoTE to the corresponding profiles' type identifiers:

  - When no type matches, the error clearly states that the LoTE Type doesn't match any of the given profiles.
  - When one type matches, but fails along the verification, only the errors of this profile are returned for clarity.
  - @owf/crypto@0.3.2
  - @owf/identity-common@0.3.2

## 0.3.1

### Patch Changes

- 541992b: Improve the error detail with profile information when validating a LoTE against a union of profiles.
  - @owf/crypto@0.3.1
  - @owf/identity-common@0.3.1

## 0.3.0

### Patch Changes

- Updated dependencies [353df0c]
  - @owf/identity-common@0.3.0
  - @owf/crypto@0.3.0

## 0.2.0

### Patch Changes

- ce47b64: Allow custom nextUpdate and listIssueDateTime in updateLoTEVersion
- b79d4ba: align package json for export
- f50ec6e: add lote package

  add package-specific exception classes (`CryptoException`, `LoTEException`, `IdentityCommonException`) extending a shared `IdentityException` base class in `@owf/identity-common`, replacing plain `Error` throws across all packages. Refactor `SLException` to also extend `IdentityException`.

- 293e5ec: Also include commonjs builds
- 1b68a03: Add support for validating a LoTE document against known LoTE profiles.
- 7021991: Correctly match distribution points and uri values are URIs.
- 9489bed: Export LoTE profile types and functions.
- Updated dependencies [b79d4ba]
- Updated dependencies [7ef6497]
- Updated dependencies [f50ec6e]
- Updated dependencies [293e5ec]
- Updated dependencies [6bd9c63]
  - @owf/identity-common@0.2.0
  - @owf/crypto@0.2.0

## 0.1.0

### Patch Changes

- f50ec6e: add lote package

  add package-specific exception classes (`CryptoException`, `LoTEException`, `IdentityCommonException`) extending a shared `IdentityException` base class in `@owf/identity-common`, replacing plain `Error` throws across all packages. Refactor `SLException` to also extend `IdentityException`.

- Updated dependencies [7ef6497]
- Updated dependencies [f50ec6e]
  - @owf/identity-common@0.1.0
  - @owf/crypto@0.1.0
