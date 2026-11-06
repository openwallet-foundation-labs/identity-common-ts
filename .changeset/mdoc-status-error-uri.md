---
'@owf/mdoc': patch
---

When the status of an mdoc can't be verified, the reason of the failed `Status information must be valid` check (and the message `IssuerAuth.verify` throws by default) now names the status list or identifier list and its URI.
