---
'@owf/eudi-registration-certificate': minor
---

Add CWT registration certificates (`signRegistrationCertificateCwt`, `decodeRegistrationCertificateCwt`), helpers to attach and decode them in mdoc and OpenID4VP requests, and `verifyRegistrationCertificate`, which checks the signature, `iat`/`exp` and the status list.

**Breaking:** `signRegistrationCertificate`, `decodeRegistrationCertificate` and `parseRegistrationCertificate` end in `Jwt`, and the signer takes a `signJwsCallback` of `@owf/jose`. All errors are a `RegistrationCertificateValidationError` with coded `issues`. `RegistrationCertificateError` is removed.
