---
'@sd-jwt/sd-jwt-vc': minor
---

The context of the `statusValidator` has `statusListJwt`: the `compact` status list token with its decoded `header` and `payload`, after its signature and claims are verified. Use it to cache the token, for example until its `exp` or for its `ttl`, without decoding it again.
