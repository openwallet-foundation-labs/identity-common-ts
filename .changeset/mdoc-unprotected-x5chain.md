---
"@owf/mdoc": patch
---

Accept a status list whose `x5chain` is in the unprotected header when a protected `x5t` matches its leaf certificate. ISO/IEC 18013-5 § 12.3.6.3 requires the chain in the protected header, but RFC 9360 allows it with that binding. The context of `IssuerAuth.verify`, `IssuerAuth.verifyStatus` and `verifyStatusListToken` now requires `crypto` to check the `x5t`.
