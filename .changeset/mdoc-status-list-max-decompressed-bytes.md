---
'@owf/mdoc': minor
---

`Verifier.verifyDeviceResponse`, `DeviceResponse.verify`, `IsoMdocDcApi.verifyResponse`, `Holder.verifyIssuerSigned`, `IssuerSigned.verify` and `IssuerAuth.verify` take a `status.maxDecompressedBytes` option, and `IssuerAuth.verifyStatus` and `verifyStatusListToken` a `maxDecompressedBytes` option: the size the status list of an mdoc may inflate to, 16 MiB by default. A status list is read in its decompressed bytes, so it takes no more memory than that.

A status list in CWT format that cannot be decompressed throws an `InvalidRevocationListError`, as one in JWT format does, instead of a `StatusListValidationError`.
