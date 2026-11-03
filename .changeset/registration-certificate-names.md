---
'@owf/eudi-registration-certificate': minor
---

The exports are named `RegistrationCertificate` instead of `WRPRC`.

**Breaking:** replace `WRPRC` with `RegistrationCertificate` in the names of the exports, e.g. `validateWRPRC` to `validateRegistrationCertificate`, `signWRPRC` to `signRegistrationCertificate`, `WRPRCError` to `RegistrationCertificateError` and `zWRPRCPayload` to `zRegistrationCertificatePayload`. Constants start with `REGISTRATION_CERTIFICATE_` instead of `WRPRC_`, e.g. `REGISTRATION_CERTIFICATE_VALIDATION_CODES`, and the builder `wrprc()` is now `registrationCertificate()`. The `name` of the errors and the messages change with it.
