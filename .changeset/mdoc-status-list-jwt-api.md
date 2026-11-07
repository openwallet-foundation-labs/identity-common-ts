---
'@owf/mdoc': patch
---

A revocation list in JWT format is verified with `verifyStatusListJwt` of `@owf/token-status-list`. A malformed `x5c` now throws `InvalidRevocationListError` instead of `UnableToExtractX5ChainFromJwtError`. An `idx` outside the status list now throws `InvalidRevocationListError` instead of a plain `Error`.
