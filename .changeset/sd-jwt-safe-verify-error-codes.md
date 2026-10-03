---
"@sd-jwt/core": patch
"@sd-jwt/sd-jwt-vc": patch
---

`safeVerify` now takes the error code from the `code` set on `SDJWTException` where the error is thrown, instead of matching substrings of the error message. Errors without a code (such as errors thrown by a custom verifier callback) are reported as `UNKNOWN_ERROR`. A custom `statusValidator` can throw an `SDJWTException` with the code `STATUS_INVALID` to report an invalid status.
