---
'@owf/token-status-list': patch
---

`fetchStatusList` rejects a response larger than `maxResponseBytes`, 16 MiB by default, which fits the largest list of Token Status List draft 16 Appendix B in either format. It checks the `Content-Length` header before reading the body, and stops reading a streamed body once it is larger than the maximum. Before, it read a body of any size into memory. `@owf/mdoc` and `@owf/eudi-registration-certificate` fetch status lists with it, and use the default.
