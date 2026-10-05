---
"@sd-jwt/core": patch
"@sd-jwt/sd-jwt-vc": patch
"@owf/mdoc": patch
---

Report the values behind failed time checks, so an error tells clock drift apart from an expired or stale token.

- `@sd-jwt/core`: a failed `iat`, `nbf`, `exp` or maximum age check names the claim, its value, the current time and the allowed clock skew, e.g. `Verify Error: JWT is expired: exp is 2026-10-05T08:00:00.000Z, current time is 2026-10-05T08:04:20.000Z (260s after exp, allowed clock skew 60s)`. The values are also in the exception's `details` (`JwtTimeClaimErrorDetails`), and `SDJWTException` has a new optional `code` (`JWT_EXPIRED`, `JWT_NOT_YET_VALID`, `JWT_TOO_OLD`).
- `@sd-jwt/core`: time check failures of the Key Binding JWT say `Key Binding JWT` instead of `JWT` and carry the new codes `KEY_BINDING_JWT_EXPIRED`, `KEY_BINDING_JWT_NOT_YET_VALID` and `KEY_BINDING_JWT_TOO_OLD`. `safeVerify` reports these codes instead of `KEY_BINDING_SIGNATURE_INVALID`.
- `@sd-jwt/sd-jwt-vc`: status list verification errors name the status list URI. A credential whose status is not valid fails with the index, the URI and the status (`Status is not valid: index 1 of status list https://example.com/status-list has status 1 (Invalid)`) and the code `STATUS_INVALID`. A custom `statusValidator` receives the URI and index as a second argument.
- `@owf/mdoc`: the reason of the MSO validity check includes the MSO's validity period and the allowed clock skew.
