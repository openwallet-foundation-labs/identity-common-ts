---
'@owf/identity-common': minor
'@owf/eudi-tl': minor
'@owf/eudi-lote': minor
'@owf/eudi-registration-certificate': minor
'@owf/eudi-access-certificate': minor
---

Validation issues have typed codes with their context, and a failed validation throws an error with the same `issues`.

- `@owf/identity-common`: issue codes are a closed union, so `issue.code === 'expired'` narrows the context. Schema issues get a code of `SCHEMA_VALIDATION_CODES` (`missing`, `invalid_type`, `invalid_value`, `too_small`, …) instead of the zod code. New: `ValidationIssues`, `parseWithSchema`, `addValidationIssue` and `zTyp`. `@owf/identity-common` now depends on zod.
- Each package throws its own validation error with `issues`: `TrustedListValidationError`, `LoTEValidationError`, `WRPRCValidationError` and `AccessCertificateValidationError`.
- `createAccessCertificate` reports all invalid options at once, with a path into the options.
- `checkOverAsking` parses the DCQL query with the `dcql` library. A credential query needs an `id`, and the `namespace`/`claim_name` form of earlier drafts is rejected (OpenID4VP 1.0 section 6).

**Breaking:** `*Exception` is renamed to `*Error` in these packages, e.g. `WRPRCException` to `WRPRCError`. Zod schemas are named `zFoo` instead of `FooSchema`, e.g. `zTrustedList`.
