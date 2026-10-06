---
"@sd-jwt/core": patch
"@sd-jwt/sd-jwt-vc": patch
"@owf/mdoc": patch
---

Expose the values behind failed time and status checks on the thrown exceptions, so callers can tell clock drift apart from an expired or stale token without parsing messages.

- `@sd-jwt/core`: a failed `iat`, `nbf`, `exp` or maximum age check throws a `JwtTimeClaimException` (a subclass of `SDJWTException`). Its `details` (`JwtTimeClaimErrorDetails`) hold the claim, its value, the current time, the allowed clock skew and, for the maximum age check, the maximum age. `SDJWTException` has a new optional `code`, here `JWT_EXPIRED`, `JWT_NOT_YET_VALID` or `JWT_TOO_OLD`; `safeVerify` uses it before falling back to message matching.
- `@sd-jwt/core`: time check failures of the Key Binding JWT say `Key Binding JWT` instead of `JWT` and carry the new codes `KEY_BINDING_JWT_EXPIRED`, `KEY_BINDING_JWT_NOT_YET_VALID` and `KEY_BINDING_JWT_TOO_OLD`. `safeVerify` reports these codes instead of `KEY_BINDING_SIGNATURE_INVALID`.
- `@sd-jwt/sd-jwt-vc`: when the status list token fails verification, the `SLException` has the status list URI in `details` and the original exception as `cause`. A credential whose status is not valid fails with code `STATUS_INVALID` and `details` `{ uri, idx, status }`. A custom `statusValidator` receives the URI and index as a second argument.
- `@owf/mdoc`: the reason of the MSO validity check includes the MSO's validity period and the allowed clock skew.
