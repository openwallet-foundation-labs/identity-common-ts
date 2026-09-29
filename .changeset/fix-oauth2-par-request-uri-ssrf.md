---
"@openid4vc/oauth2": patch
"@openid4vc/openid4vci": patch
---

Reject a pushed authorization request or interactive authorization request containing a `request_uri` parameter with an `invalid_request` error, instead of fetching the `request_uri`.
