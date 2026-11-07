---
"@openid4vc/openid4vp": minor
---

`parseOpenid4vpAuthorizationRequest` now rejects a DC API or IAE request passed as a URI, as these are always passed as a JSON object (OpenID4VP 1.0 Appendix A.3, OpenID4VCI 1.1 Section 6.2.1.1).

`createOpenid4vpAuthorizationRequest` now rejects an unsigned request whose client identifier prefix requires a signed request, as only `pre-registered` and `redirect_uri` can be used unsigned (OpenID4VP 1.0 Section 5.9.3).

**Breaking:** for a DC API or IAE request, the `authorizationRequest` returned by `createOpenid4vpAuthorizationRequest` is now the JSON object to pass to the wallet instead of a URI: the request payload, or `{ client_id, request }` when signed. Its type now includes these objects, so check for a string before treating it as a URL.
