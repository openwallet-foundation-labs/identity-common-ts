---
'@owf/mdoc': minor
---

**Breaking:** `trustedIssuanceChain` in the results of `IssuerAuth.verify`, `IssuerSigned.verify` and `DeviceResponse.verify` is now typed as optional. It was already undefined at runtime when `disableCertificateChainValidation` is set, or when chain validation failed with a verification callback that does not throw, but the type claimed it was always an array.
