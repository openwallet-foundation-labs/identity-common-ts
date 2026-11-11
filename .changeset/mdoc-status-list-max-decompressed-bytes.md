---
'@owf/mdoc': minor
---

`Verifier.verifyDeviceResponse`, `DeviceResponse.verify`, `IsoMdocDcApi.verifyResponse`, `Holder.verifyIssuerSigned`, `IssuerSigned.verify`, `IssuerAuth.verify` and `IssuerAuth.verifyStatus` take a `maxStatusListDecompressedBytes` option, and `verifyStatusListToken` a `maxDecompressedBytes` option: the size the status list of an mdoc may inflate to, 16 MiB by default. A status list is read in its decompressed bytes, so it takes no more memory than that. They also take a `maxStatusListResponseBytes` option, and `verifyStatusListToken` a `maxResponseBytes` option: the size of the response that serves the status list, 16 MiB by default, as `fetchStatusList` of `@owf/token-status-list` limits it.

A status list in CWT format that cannot be decompressed throws an `InvalidRevocationListError`, as one in JWT format does, instead of a `StatusListValidationError`.
