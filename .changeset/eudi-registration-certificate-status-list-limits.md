---
'@owf/eudi-registration-certificate': minor
---

`verifyRegistrationCertificate` takes `maxStatusListResponseBytes` and `maxStatusListDecompressedBytes`, and `verifyRegistrationCertificateStatus` takes `maxResponseBytes` and `maxDecompressedBytes`: the size of the response that serves the status list of a registration certificate, and the size the list may inflate to, each 16 MiB by default. A larger response is reported as `status_list_unavailable`, and a larger list as `invalid_status_list`.
