---
'@owf/identity-common': minor
'@owf/eudi-tl': minor
'@owf/eudi-lote': minor
'@owf/eudi-registration-certificate': minor
'@owf/eudi-access-certificate': minor
---

Report validation results as findings of one shape, so the validators of trusted lists, LoTEs, registration certificates and access certificates can be consumed the same way, for example to show which element of a parsed document conforms and which does not.

- `@owf/identity-common` adds `Finding` (`severity`, `code`, `path`, `message` and an optional `requirement`), `FindingSeverity`, `schemaIssueToFinding` for zod and other schema issues, and `hasErrorFindings`. The `path` holds property names and array indices as numbers, and is empty for a finding about the value as a whole.
- `validateTrustedList`, `validateTrustedListProfile`, `validateLoTE`, `validateLoTEProfile`, `validateWRPRC`, `validateWRPRCPayload`, `validateWRPRCJWTHeader`, `validateLegalPersonWRPRC`, `validateNaturalPersonWRPRC` and `validateAccessCertificate` return `findings` next to `errors` and `warnings`, which are unchanged. Schema issues carry the zod issue code. The findings of a LoTE profile validation carry no summary entry for the document as a whole.
- `@owf/eudi-tl` adds `TRUSTED_LIST_VALIDATION_CODES` and `@owf/eudi-lote` adds `LOTE_VALIDATION_CODES`, the codes of their profile checks. The findings of `@owf/eudi-registration-certificate` carry the ETSI TS 119 475 requirement where a check has one.
- `AccessCertificateValidationIssue` is now a `Finding`, so the errors and warnings of `validateAccessCertificate` carry a `path` into the access certificate, e.g. `['certificate', 'subject', 'organizationIdentifier']`.
