---
'@openid4vc/oauth2': patch
'@openid4vc/openid4vci': patch
---

The `error_description` of the `invalid_request` error for a request that does not validate is now one line, as RFC 6749 Section 5.2 doesn't allow line breaks and quotes in it. The validation issues are still in the error message. This applies to `parseAccessTokenRequest`, `parsePushedAuthorizationRequest` and `parseAuthorizationChallengeRequest` of `Oauth2AuthorizationServer`, and `parseInteractiveAuthorizationRequest` of `Openid4vciIssuer`. The new `Oauth2ServerErrorResponseError.fromValidationIssues` creates such an error.
