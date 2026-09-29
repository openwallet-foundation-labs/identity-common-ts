---
"@openid4vc/oauth2": patch
---

Reject an access token request with `invalid_grant` when it contains a `code_verifier` but no `pkce` options are passed to the verify function (the grant is not bound to a code challenge). This prevents a PKCE downgrade attack as described in RFC 9700 §4.8.2, where a code obtained without PKCE is injected into the flow of a client that does use PKCE.
