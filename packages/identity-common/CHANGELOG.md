# @owf/identity-common

## 0.7.0

### Minor Changes

- 23f227b: Validators return one list of issues of one shape, so the validators of trusted lists, LoTEs, registration certificates and access certificates can be consumed the same way, for example to show which element of a parsed document conforms and which does not.
  
  **Breaking:** `validateTrustedList`, `validateTrustedListProfile`, `validateLoTE`, `validateLoTEProfile`, `validateWRPRC`, `validateWRPRCPayload`, `validateWRPRCJWTHeader`, `validateLegalPersonWRPRC`, `validateNaturalPersonWRPRC` and `validateAccessCertificate` return `{ valid, issues }` instead of `errors` and `warnings`. Use `validationErrors(result)` for the errors only.
  
  - `@owf/identity-common` adds:
    - `ValidationIssue` (`severity`, `code`, `path`, `message`, and an optional `requirement` and `context`) and `ValidationResult`. The severity is `error`, `warning` or `info`, and only errors make a result invalid. The `path` holds property names and array indices as numbers, and is empty for an issue about the value as a whole.
    - `VALIDATION_CODES`, codes for checks that recur across specifications (`invalid_typ`, `expired`, `not_yet_valid`, `expires_before_issued`), each with a typed context in `ValidationIssueContexts`, e.g. `{ expected, actual }` for `invalid_typ`. `ValidationIssueOf<Code>` types the issues of a validator, so checking the code narrows the context.
    - `schemaIssueToValidationIssue` for zod and other schema issues. A custom zod issue whose `params` are `ValidationIssueParams` gets their code, severity, requirement and context.
    - `toValidationResult`, `validationErrors`, `hasValidationErrors` and `prefixIssuePaths`.
  - Schema issues carry the zod issue code. `@owf/eudi-tl` adds `TRUSTED_LIST_VALIDATION_CODES` and `@owf/eudi-lote` adds `LOTE_VALIDATION_CODES`, the codes of their profile checks.
  - `validateLoTEProfile` no longer adds a summary error for the document as a whole. A document whose `LoTEType` matches none of the profiles gets an `unexpected_lote_type` issue for each profile.
  - `@owf/eudi-registration-certificate`: the issues carry the ETSI TS 119 475 requirement where a check has one. A `typ` other than `rc-wrp+jwt` is reported as `invalid_typ`, and `exp` at or before `iat` as `expires_before_issued` (before: `exp_before_iat`, and `WRPRC_VALIDATION_CODES.EXP_BEFORE_IAT` is now `EXPIRES_BEFORE_ISSUED`). `ValidationError` is removed.
  - `@owf/eudi-access-certificate`: the issues carry a `path` into the access certificate, e.g. `['certificate', 'subject', 'organizationIdentifier']`. The values of `ACCESS_CERTIFICATE_VALIDATION_CODES` are now in lower case, such as `missing_policy`, and `expired` and `not_yet_valid` carry the date as context.

## 0.6.2

No changes in this release.

## 0.6.1

### Patch Changes

- bf9b7c8: Add `createAcceptHeader`, which asks for media types in order of preference with decreasing `q` values, never below 0.1, and drops duplicates. `createZodFetcher` now uses it, so `@openid4vc/utils` depends on `@owf/identity-common`.

## 0.6.0

No changes in this release.

## 0.5.0

### Minor Changes

- b4105be: Drop the CommonJS build from all packages; only ESM is now published. All environments targeted by this library support ESM natively. This removes the dual-package hazard that caused `instanceof` checks to fail in Metro/Hermes and similar single-module-system runtimes.

## 0.4.2

No changes in this release.

## 0.4.1

No changes in this release.

## 0.4.0

### Minor Changes

- b7e7f15: Add `dateToSeconds`, `secondsToDate` and `nowInSeconds` to `@owf/identity-common`, and use them in `@owf/eudi-wrprc` in place of inline `* 1000` and `/ 1000` arithmetic.
  
  Type the codes that `validateWRPRCPayload` emits. `WRPRC_VALIDATION_CODES` and the `WRPRCValidationCode` union are exported, so a calling application can branch on a specific failure instead of matching message text. The `code` field stays open to strings because schema issues forward zod's own codes. `ValidationError` and `ValidationResult` are now exported as well.
- 65a7173: Add `base64urlDecodeJson` to `@owf/identity-common`, and use it in `decodeJwt`. Bytes that are not valid UTF-8 are now rejected instead of being decoded to a different string, and invalid base64url, UTF-8 or JSON in a JWT header or payload all throw `IdentityCommonException('Invalid JWT as input')`, without exposing parser details.
  
  `@sd-jwt/core` now uses these functions from `@owf/identity-common` for decoding JWTs and disclosures, instead of its own implementation. Errors are still thrown as `SDJWTException` with the same messages.
- 65a7173: Build all base64, base64url, UTF-8 and JSON encoding on a single implementation in `@owf/identity-common`.
  
  - `base64` and `base64url` share one codec. Decoding input with an impossible length (a single trailing character) now throws instead of returning a corrupt byte.
  - `stringToBytes` and `bytesToString` use `TextEncoder` and `TextDecoder`, which must now be available in the environment (see the React Native notes in the README). `bytesToString` and `base64urlDecode` accept `{ fatal: true }` to throw on invalid UTF-8 instead of replacing it.
  - `base64urlDecodeJson` and `decodeJwt` build on these layers.
  
  `@owf/crypto`, `@owf/eudi-jades`, `@owf/eudi-sca` and `@owf/token-status-list` use these functions instead of their own `TextEncoder`, `TextDecoder` and `JSON.parse` calls. JSON decoded from base64url (JAdES headers and `etsiU` values, transaction data, and status list token payloads) is now strict about UTF-8.

### Patch Changes

- 5934a14: Add `extractMediaType` and `isMediaType` to `@owf/identity-common` for comparing `Content-Type` header values against expected media types, ignoring casing and parameters.
  
  `fetchStatusList` now uses `isMediaType` instead of an exact string match on the `Content-Type` response header, so a status list served as e.g. `application/statuslist+jwt; charset=utf-8` or `Application/StatusList+CWT` is no longer rejected.

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
