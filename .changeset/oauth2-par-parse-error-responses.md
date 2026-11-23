---
'@openid4vc/oauth2': patch
---

`parsePushedAuthorizationRequest` throws an `Oauth2ServerErrorResponseError` for a request it cannot parse, as its documentation says, instead of the error of `@owf/identity-common` or `@owf/jose`. The error is `invalid_request` for a request that is neither an authorization request nor a JAR (RFC 9126 Section 2.3), and `invalid_request_object` for a JAR whose `request` is not a JWT (RFC 9101 Section 7), with the original error as `cause`.
