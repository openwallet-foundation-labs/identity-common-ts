---
"@owf/mdoc": minor
---

Add an optional `revocationListCache` to `MdocContext`, with a `get`/`set` pair per revocation mechanism. A cached status list or identifier list token is used in place of a request, and is still verified against the current time and trust anchors before use. `set` receives a token whose signature and claims have verified, so the `ttl` and `exp` a cache bases its freshness policy on are the issuer's.
