---
"@openid4vc/openid4vp": patch
---

`parseOpenid4vpAuthorizationRequest` now rejects a DC API request passed as a URI, as it is always passed to the wallet as a JSON object (OpenID4VP 1.0 Appendix A.2). An unsigned request passed as a URI must use the `pre-registered` or `redirect_uri` client identifier prefix, as the other prefixes require a signed request (OpenID4VP 1.0 Section 5.9.3).
