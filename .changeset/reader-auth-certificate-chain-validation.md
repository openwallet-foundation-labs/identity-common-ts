---
'@owf/mdoc': minor
---

Reader auth certificate chain validation is no longer skipped silently. `ReaderAuth.verify`, `Holder.verifyDeviceRequest` and `IsoMdocDcApi.parseRequest` now report a FAILED `Reader certificate chain must be trusted` check when a doc request carries reader auth but no trusted reader certificates are provided, so `defaultVerificationCallback` throws. Before, only the signature was verified, and any self-signed reader certificate was accepted.

To only verify the signature, pass `disableCertificateChainValidation: true` to `ReaderAuth.verify` and `Holder.verifyDeviceRequest`, or `disableReaderCertificateChainValidation: true` to `IsoMdocDcApi.parseRequest`.
