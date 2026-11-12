---
'@owf/token-status-list': minor
---

`fetchStatusList` rejects a response larger than 16 MiB, which fits the largest list of Token Status List draft 16 Appendix B in either format, or than the `statusList` limit of its new `fetchLimits` option (see `FetchLimits` of `@owf/identity-common`). It checks the `Content-Length` header before reading the body, and stops reading a streamed body once it is larger than the maximum. Before, it read a body of any size into memory. Its `customFetcher` gets `{ type: 'statusList' }` as its third argument.
