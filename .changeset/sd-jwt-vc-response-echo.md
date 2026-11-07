---
'@sd-jwt/sd-jwt-vc': patch
---

The default status list and type metadata fetchers of `SdJwtVcInstance` no longer put the body of a fetched response into their errors, and type metadata that is not valid JSON no longer gives a `SyntaxError` that quotes the body. `verify` and `safeVerify` pass these errors on, so they could return the response of an internal endpoint to whoever presented the credential, for example when a verifier accepts credentials of issuers it does not know.
