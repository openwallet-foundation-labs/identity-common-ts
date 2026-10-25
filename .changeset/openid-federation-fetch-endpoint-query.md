---
'@owf/openid-federation': patch
---

Keep the query component of a `federation_fetch_endpoint` (Section 5.1.1 of OpenID Federation 1.0). `sub` is appended with `&`, so a fetch endpoint `https://ta.example.org/fetch?tenant=a` is requested as `https://ta.example.org/fetch?tenant=a&sub=...` instead of `https://ta.example.org/fetch?tenant=a?sub=...`. This applies to `fetchEntityStatement`, `resolveTrustChains` and `resolveTrustChainsWithFailures`.
