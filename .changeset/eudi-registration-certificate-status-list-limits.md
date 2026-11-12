---
'@owf/eudi-registration-certificate': minor
---

`verifyRegistrationCertificate` takes `maxStatusListDecompressedBytes`, and `verifyRegistrationCertificateStatus` takes `maxDecompressedBytes`: the size the status list of a registration certificate may inflate to, 16 MiB by default. The response that serves the status list is limited to 16 MiB, or the `statusList` limit of the new `fetchLimits` of the callbacks (see `FetchLimits` of `@owf/identity-common`). A larger response is reported as `status_list_unavailable`, and a larger list as `invalid_status_list`. The `fetch` callback gets `{ type: 'statusList' }` as its third argument.
