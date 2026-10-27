---
'@owf/identity-common': patch
'@openid4vc/utils': patch
---

Add `createAcceptHeader`, which asks for media types in order of preference with decreasing `q` values, never below 0.1, and drops duplicates. `createZodFetcher` now uses it, so `@openid4vc/utils` depends on `@owf/identity-common`.
