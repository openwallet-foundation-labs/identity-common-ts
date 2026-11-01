---
"@openid4vc/openid4vp": patch
---

The `client_id` of an unsigned DC API request is now ignored, as required by OpenID4VP 1.0 Appendix A.2. Before, a web page could set any `client_id` in an unsigned request, and the wallet used it as the client. `resolveOpenid4vpAuthorizationRequest` and `validateOpenid4vpClientId` now identify the client by the origin, and the resolved `authorizationRequestPayload` no longer contains the `client_id`.

`getOpenid4vpClientId` now rejects a `client_id` with the reserved `origin:` or `web-origin:` prefix.
