---
'@owf/mdoc': patch
---

A single certificate in an `x5chain` header is encoded as a byte string instead of an array with one byte string, as RFC 9360 and the examples of ISO/IEC 18013-5 Annex D encode it. This applies to the issuer auth of `Issuer.sign` and `IssuerSignedBuilder.sign`, and the reader auth of `IsoMdocDcApi.createRequest`. A chain of more than one certificate is still an array, and both forms are accepted when decoding.
