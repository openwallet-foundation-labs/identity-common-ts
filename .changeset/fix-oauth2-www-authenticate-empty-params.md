---
"@openid4vc/oauth2": patch
"@openid4vc/utils": patch
---

Omit absent `error`, `error_description` and `scope` parameters from the `WWW-Authenticate` header produced by `Oauth2ResourceUnauthorizedError.toHeaderValue()`. Previously they were emitted as bare parameter names (e.g. `Bearer error, error_description, scope`), which is not a valid challenge per RFC 9110 §11.6.1. `encodeWwwAuthenticateHeader` now skips payload entries with an `undefined` value, while `null` values are still encoded as bare parameter names.
