---
'@owf/openid-federation': patch
---

`fetchEntityConfiguration`, `resolveTrustChains` and `resolveTrustChainsWithFailures` only fetch from https URLs: an entity id, `authority_hints` and the `federation_*_endpoint` metadata must be https URLs (OpenID Federation 1.0 Sections 1.2 and 5.1.1). These are fetched while a trust chain is resolved, before it is trusted, so an entity could make the resolver request any URL, such as an internal http endpoint.
