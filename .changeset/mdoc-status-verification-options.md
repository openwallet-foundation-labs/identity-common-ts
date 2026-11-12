---
'@owf/mdoc': minor
---

`Verifier.verifyDeviceResponse`, `DeviceResponse.verify`, `IsoMdocDcApi.verifyResponse`, `Holder.verifyIssuerSigned`, `IssuerSigned.verify` and `IssuerAuth.verify` take the options for the status check of an mdoc in one `status` option of the new `StatusVerificationOptions` type: `disableValidation` and `maxDecompressedBytes`. The same object can be passed to each of them.

**Breaking:** `disableStatusValidation: true` becomes `status: { disableValidation: true }`.
