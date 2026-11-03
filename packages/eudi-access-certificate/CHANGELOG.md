# @owf/eudi-access-certificate

## 0.6.0

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

### Patch Changes

- Updated dependencies [23f227b]
  - @owf/identity-common@0.7.0
  - @owf/x509@0.7.0

## 0.5.4

### Patch Changes

- @owf/identity-common@0.6.2
  - @owf/x509@0.6.2

## 0.5.3

### Patch Changes

- Updated dependencies [bf9b7c8]
  - @owf/identity-common@0.6.1
  - @owf/x509@0.6.1

## 0.5.2

### Patch Changes

- @owf/identity-common@0.6.0
  - @owf/x509@0.6.0

## 0.5.1

No changes in this release.

## 0.5.0

### Minor Changes

- b4105be: Drop the CommonJS build from all packages; only ESM is now published. All environments targeted by this library support ESM natively. This removes the dual-package hazard that caused `instanceof` checks to fail in Metro/Hermes and similar single-module-system runtimes.
- 6bcea3c: Add `@owf/x509` for environment agnostic X.509 certificate and CRL parsing, creation, signature verification and revocation checking, and `@owf/eudi-access-certificate` on top of it to parse, validate and create EUDI wallet-relying party access certificates per ETSI TS 119 411-8. Signing and signature verification are callbacks, so private keys are never passed to the libraries.

### Patch Changes

- Updated dependencies [b4105be]
- Updated dependencies [6bcea3c]
  - @owf/identity-common@0.5.0
  - @owf/x509@0.5.0
