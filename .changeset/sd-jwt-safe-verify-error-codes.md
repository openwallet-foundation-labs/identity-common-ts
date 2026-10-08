---
"@sd-jwt/core": minor
"@sd-jwt/sd-jwt-vc": patch
---

`safeVerify` now takes the error code from the `code` set on `SDJwtException` where the error is thrown, instead of matching substrings of the error message. Errors without a code (such as errors thrown by a custom verifier callback) are reported as `UNKNOWN_ERROR`.

**Breaking:** the `SDJwtException` constructor takes an options object instead of positional arguments: `new SDJwtException(message, { details, code, cause })`. Replace `new SDJwtException(message, details)` with `new SDJwtException(message, { details })`. `JwtTimeClaimException` takes the same options, with `details` and `code` required.

In `@sd-jwt/sd-jwt-vc`, `safeVerify` keeps the code of an `SDJwtException` thrown during the status and type metadata checks, for example `STATUS_INVALID` from a custom `statusValidator`, and only falls back to `STATUS_VERIFICATION_FAILED` or `VCT_VERIFICATION_FAILED` for errors without a code.
