---
'@owf/mdoc': patch
'@owf/cose': patch
---

`IssuerAuth.verify` and `ReaderAuth.verify` check a protected `x5t`, if present. It must use SHA-256, as the second edition of ISO/IEC 18013-5 (12.3.4 and 12.5.4) requires, and match the issuer or reader certificate. The new checks are `The x5t in the protected header, if present, must be SHA-256 and match the issuer certificate` and the same for the reader certificate. An IssuerAuth or ReaderAuth without an `x5t` still verifies.

`ReaderAuth.verify` and `Holder.verifyDeviceRequest` now need `crypto` in their context.

`Issuer.sign`, `IssuerSignedBuilder.sign` and the `readerAuth` option of `IsoMdocDcApi.createRequest` accept `includeX5t`. It adds a SHA-256 `x5t` of the leaf certificate to the protected header, as the second edition recommends. It's off by default, because the first edition has only `alg` in the protected header.

`@owf/cose` exports `verifyX5t`, which checks the protected `x5t` of a COSE structure against a certificate, and a `HashAlgorithm` enum with the COSE value of SHA-256.
