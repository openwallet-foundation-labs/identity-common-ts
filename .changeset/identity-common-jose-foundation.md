---
'@owf/identity-common': minor
---

`zTyp` compares the `typ` as RFC 7515 section 4.1.9 does: in any casing, and with or without the `application/` prefix. `parseWithErrorHandling` takes an optional error class to throw. An issue whose context has only optional members no longer needs `context: {}`. New: the codes `claim_missing`, `claim_value_mismatch`, `invalid_crit` and `unsupported_crit`, `ValidationError.findIssue(code)`, `isJwtTyp`, `zNonEmptyString`, `zBase64Url` and `MarkOptional`.
