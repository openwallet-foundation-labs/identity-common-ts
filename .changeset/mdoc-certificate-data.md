---
"@owf/mdoc": minor
---

`IssuerSigned.verify` reads the document signer certificate with one `x509.getCertificateData` call, instead of a lookup per field. `IssuerAuth.verify`, `IssuerSigned.verify` and each document result of `DeviceResponse.verify` return it as `documentSignerCertificate`.

**Breaking:** the `x509.getSubjectNameField` context callback is removed. Return `subject.countryName` and `subject.stateOrProvinceName`, the `C` and `ST` of the subject distinguished name, from `x509.getCertificateData` instead. `IssuerAuth.getIssuingCountry` and `IssuerAuth.getIssuingStateOrProvince` are removed, read both from `documentSignerCertificate.subject`. `IssuerSignedItem.matchCertificate` takes the certificate data instead of the issuer auth and the context.
