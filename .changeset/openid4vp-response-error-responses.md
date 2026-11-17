---
'@openid4vc/openid4vp': patch
---

`parseOpenid4vpAuthorizationResponse`, `parseJarmAuthorizationResponse`, `verifyJarmAuthorizationResponse` and `validateOpenid4vpAuthorizationResponsePayload` throw an `Oauth2ServerErrorResponseError` with error `invalid_request` (RFC 6749 Section 5.2) for an authorization response that cannot be decoded or parsed, instead of the error of `@owf/jose`, `@owf/identity-common` or `@openid4vc/utils`, which is now the `cause`. An authorization error response of the wallet still throws an `Openid4vpAuthorizationResponseError`.
