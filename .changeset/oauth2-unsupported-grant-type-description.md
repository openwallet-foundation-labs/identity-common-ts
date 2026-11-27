---
'@openid4vc/oauth2': patch
---

`parseAccessTokenRequest` no longer puts the `grant_type` of the request in the `error_description` and message of the `unsupported_grant_type` error. The grant type can be any string, while RFC 6749 Section 5.2 only allows printable ASCII without `"` and `\` in `error_description`.
