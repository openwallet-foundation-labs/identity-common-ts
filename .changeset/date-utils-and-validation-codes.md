---
"@owf/identity-common": minor
"@owf/eudi-wrprc": minor
---

Add `dateToSeconds`, `secondsToDate` and `nowInSeconds` to `@owf/identity-common`, and use them in `@owf/eudi-wrprc` in place of inline `* 1000` and `/ 1000` arithmetic.

Type the codes that `validateWRPRCPayload` emits. `WRPRC_VALIDATION_CODES` and the `WRPRCValidationCode` union are exported, so a calling application can branch on a specific failure instead of matching message text. The `code` field stays open to strings because schema issues forward zod's own codes. `ValidationError` and `ValidationResult` are now exported as well.
