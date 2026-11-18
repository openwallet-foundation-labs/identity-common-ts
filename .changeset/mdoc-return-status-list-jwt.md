---
'@owf/mdoc': minor
---

`IssuerAuth.verify`, `IssuerAuth.verifyStatus`, `IssuerSigned.verify`, `Holder.verifyIssuerSigned` and `DeviceResponse.verify` return a status list served as a JWT as `statusListJwt`, next to `statusList` for one served as a CWT. `VerifiedStatusListJwt` now includes the fetched `jwt`, so it can be cached.
