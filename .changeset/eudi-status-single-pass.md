---
'@owf/eudi-registration-certificate': minor
'@owf/eudi-jades': minor
'@owf/eudi-lote': patch
'@owf/token-status-list': patch
'@owf/identity-common': minor
---

Decode and validate once where one flow did it several times.

`verifyRegistrationCertificate` decodes the registration certificate once instead of four times, and does not decode again what `decodeRegistrationCertificateJwt` or `decodeRegistrationCertificateCwt` returned. It is verified as it is passed, so pass it unmodified. A decoded CWT registration certificate is the new type `DecodedRegistrationCertificateCwt`, which also holds the decoded CWT as `registrationCertificateCwt`. The payload is validated once per decode instead of three times. Both decode functions can be called without `accessCertificateSub`, to read a registration certificate before the subject of the access certificate is known. `verifyRegistrationCertificate` always compares it (ETSI TS 119 475 clause 4.5 and GEN-5.1.1-02).

**Breaking:** a decoded JWT registration certificate is now the decoded JWT, as `decodeJwt` of `@owf/jose` returns it, with the header and payload of the registration certificate. Its compact JWS is `compact`, which was `jws`. This is what `decodeRegistrationCertificateJwt`, `decodeOpenid4vpRegistrationCertificate`, `decodeMdocRegistrationCertificate` and `verifyRegistrationCertificate` return for a JWT, as the new type `DecodedRegistrationCertificateJwt`.

**Breaking:** `verifyRegistrationCertificate` no longer takes what a sign function returned. Pass its `jws` or `cwt`.

`@owf/eudi-jades` adds `decodeJadesJwt`, and `verifyJadesJwt` takes its result as `jwt`. It is verified as it is passed, like `verifyJwt` of `@owf/jose` does, so pass what `decodeJadesJwt` returned unmodified. Both reject a JWT with `b64` in `crit` unless `understoodCriticalParameters` names it, as `decodeJwt` of `@owf/jose` does.

`verifyStatusListJwt` no longer decodes a decoded token again, and inflates the list with its own `maxDecompressedBytes`. Before, only the `compact` of a decoded token was used. Now it is verified as it is passed too, so pass what `decodeStatusListJwt` returned unmodified.

`fetchStatusList` uses the body as it was read instead of copying it out of the response, through the new `fetchBodyWithLimits` of `@owf/identity-common`. `validateLoteProfile` reuses the strict schema of a profile instead of building it on every call.
