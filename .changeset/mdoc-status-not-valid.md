---
"@owf/mdoc": minor
---

Report a status list entry that is not Valid as `StatusListEntryNotValidError` with its `uri`, `idx` and `status`, so it can be told apart from a status list that fails verification. It extends `InvalidRevocationListError`. `IssuerAuth.verify` adds it, or a revoked identifier, to the failed check as a `VerificationAssessmentResult`; narrow `result` on `type` before reading `match`.
