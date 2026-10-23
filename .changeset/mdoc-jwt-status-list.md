---
"@owf/mdoc": patch
---

Accept a status list served as a JWT as a fallback. `verifyStatusListToken` still requests a CWT first, verifies a JWT (ES256/384/512, signer from `x5c`) with the same signer, claim and status checks, and returns it as `statusListJwt` (`IssuerAuth.verify` verifies it but does not return it); `statusListCwt` is now optional and `JwtNotSupportForStatusListError` is deprecated.
