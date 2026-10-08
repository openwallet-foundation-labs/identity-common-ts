---
'@openid4vc/oauth2': patch
---

`verifyJarRequest` takes a `now` option and verifies the request object at that time rather than at the current time. `verifyPushedAuthorizationRequest` passes its `now` on.
