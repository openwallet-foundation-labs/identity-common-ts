---
'@openid4vc/oauth2': patch
---

The `redirect_uri` can be verified. Before, it was not checked at all, so an authorization server that relied on this package sent the authorization code to any `redirect_uri` in the request and accepted any `redirect_uri` when the code was redeemed:

- `verifyAuthorizationRequest`, `verifyPushedAuthorizationRequest`, `verifyAuthorizationChallengeRequest` and `verifyInteractiveAuthorizationInitialRequest` take `allowedRedirectUris`, the redirect URIs registered for the client. The `redirect_uri` must exactly match one of them (RFC 9700 Section 4.1.3), and can only be left out if a single one is registered (RFC 6749 Section 3.1.2.3). On this error, do not redirect to the `redirect_uri`.
- `verifyAuthorizationCodeAccessTokenRequest` takes `expectedRedirectUri`, the `redirect_uri` of the authorization request the code was issued for. The access token request must contain the identical `redirect_uri` (RFC 6749 Section 4.1.3).

An authorization server that does not check the `redirect_uri` itself should pass both.
