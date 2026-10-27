---
'@owf/token-status-list': patch
---

`fetchStatusList` asks for its `acceptedFormats` in order of preference. `verifyStatusListJwtHeader` now requires an `alg` header and returns the header it verified, typed with `alg` and `typ`. `verifyStatus` checks the header and claims before it reads the status list, reports an unreadable list as an `SLException`, and a status that is not Valid as the new `StatusListEntryNotValidException`, an `SLException` with `idx` and `status`.
