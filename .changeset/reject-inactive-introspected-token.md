---
'@openid4vc/oauth2': patch
---

`verifyResourceRequest` now rejects an opaque access token when token introspection reports it as inactive. Before, a response with `active: false` was accepted, so revoked, expired or unknown tokens passed verification.
