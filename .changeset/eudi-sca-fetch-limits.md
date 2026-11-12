---
'@owf/eudi-sca': minor
---

`fetchCredentialMetadata` reads the response within 10 MiB, or the `credentialMetadata` limit of its new `fetchLimits` parameter (see `FetchLimits` of `@owf/identity-common`). Before, it read a response of any size. Its `customFetcher` gets `{ type: 'credentialMetadata' }` as its third argument.
