---
"@openid4vc/oauth2": patch
"@openid4vc/openid4vp": patch
---

`zJarAuthorizationRequest` now requires `request` or `request_uri`. Before, it matched any object. An unsigned request that failed the regular schema was accepted without validation in `resolveOpenid4vpAuthorizationRequest`, `parseOpenid4vpAuthorizationRequest`, `parsePushedAuthorizationRequest` and `parseInteractiveAuthorizationRequest`. For OpenID4VP, this skipped the https check on `response_uri`, so a wallet could send the presentation over plain http.
