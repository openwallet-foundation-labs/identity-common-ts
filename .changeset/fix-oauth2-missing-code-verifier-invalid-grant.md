---
"@openid4vc/oauth2": patch
---

Respond with `invalid_grant` instead of `invalid_request` when the `code_verifier` is missing from an access token request for an authorization code bound to a PKCE code challenge, as required by RFC 7636 §4.6.
