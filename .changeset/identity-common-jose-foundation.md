---
'@owf/identity-common': minor
---

`zTyp` compares the `typ` as RFC 7515 section 4.1.9 does: in any casing, and with or without the `application/` prefix. The value is kept as received. `parseWithErrorHandling` takes an optional error class, so a package throws its own validation error. An issue whose context has only optional members, such as `invalid_value`, no longer needs `context: {}`. New common codes: `claim_missing` and `claim_value_mismatch` for claims that do not verify, and `invalid_crit` and `unsupported_crit` for the `crit` header parameter (RFC 7515 section 4.1.11). `ValidationError.findIssue(code)` returns the first issue with that code, typed by it. New: `isJwtTyp`, `zNonEmptyString`, `zBase64Url` and the `MarkOptional` type.
