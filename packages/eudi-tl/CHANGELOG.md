# @owf/eudi-tl

## 0.6.0

### Minor Changes

- 23f227b: `parseTrustedList` returns the `SchemeTerritory` of the list as `schemeTerritory`, the country code to pass to `getPointerSigningCertificates` to find the certificates its signer must have.
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

## 0.5.4

### Patch Changes

- @owf/identity-common@0.6.2

## 0.5.3

### Patch Changes

- Updated dependencies [bf9b7c8]
  - @owf/identity-common@0.6.1

## 0.5.2

### Patch Changes

- @owf/identity-common@0.6.0

## 0.5.1

No changes in this release.

## 0.5.0

### Minor Changes

- b4105be: Drop the CommonJS build from all packages; only ESM is now published. All environments targeted by this library support ESM natively. This removes the dual-package hazard that caused `instanceof` checks to fail in Metro/Hermes and similar single-module-system runtimes.

### Patch Changes

- Updated dependencies [b4105be]
  - @owf/identity-common@0.5.0

## 0.4.2

### Patch Changes

- @owf/identity-common@0.4.2

## 0.4.1

### Patch Changes

- @owf/identity-common@0.4.1

## 0.4.0

### Minor Changes

- fb11a48: Expose ASN.1 parse options for the X.509 certificates embedded in a trusted list: `parseTrustedList`, `loadTrustedList` and `loadEuLotl` now accept `certificateParseOptions`, forwarding `asn1js.fromBER` resource limits (`maxDepth`, `maxNodes`, `maxContentLength`) so callers can bound the work done on untrusted input. Certificate parsing moved from `@peculiar/x509` to `@peculiar/asn1-x509`, which needs no global `Reflect` polyfill; the derived `subjectKeyIdentifier` values are unchanged
- 59b304c: New package: parse and verify ETSI TS 119 612 XML Trusted Lists (companion to @owf/eudi-lote for TS 119 602 JSON), exposing normalized trust anchors, caller-supplied profile validation, and XAdES signature verification with pinned scheme operator certificates and a caller-installable crypto engine (`setTrustedListCrypto`)
- 59b304c: Follow the EU trust hierarchy: trusted list pointers now expose the certificates the pointed-to list is signed with (`getPointerSigningCertificates`), and the EU LOTL signing certificates ship as pinned default anchors (`EU_LOTL_SIGNING_CERTIFICATES`, `getEuLotlTrustAnchors`, `verifyEuLotlSignature`, `loadEuLotl`) with provenance and a refresh script

### Patch Changes

- Updated dependencies [b7e7f15]
- Updated dependencies [5934a14]
- Updated dependencies [65a7173]
- Updated dependencies [65a7173]
  - @owf/identity-common@0.4.0
