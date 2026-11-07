---
'@owf/mdoc': minor
---

With `disableCertificateChainValidation`, `IssuerAuth.verify`, and through it `Verifier.verifyDeviceResponse`, `DeviceResponse.verify`, `IsoMdocDcApi.verifyResponse`, `Holder.verifyIssuerSigned` and `IssuerSigned.verify`, no longer fetch the status list or identifier list of the MSO, and report a `WARNING` check that the status was not checked. Without chain validation, the MSO is only known to be signed with the key of its own certificate, so whoever presented a self-signed MSO could make the verifier request a URI of their choice, and read its status code back from the failed check.

**Breaking:** a verifier that establishes the trust in the issuer itself checks the status by calling `IssuerAuth.verifyStatus` after that, for example `issuerSigned.issuerAuth.verifyStatus({ disableCertificateChainValidation: true }, ctx)`.
