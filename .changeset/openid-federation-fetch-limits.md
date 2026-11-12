---
'@owf/openid-federation': minor
---

`fetchEntityConfiguration`, `fetchEntityStatement` and `resolveTrustChains` read every response within 10 MiB, or the limits of their new `fetchLimits` option (see `FetchLimits` of `@owf/identity-common`). Before, they read a response of any size. The `fetchCallback` gets `{ type: 'entityConfiguration' }` or `{ type: 'entityStatement' }` as its third argument.

**Breaking:** `fetcher.get` and `fetcher.post` take a `type`, `'entityConfiguration'` or `'entityStatement'`.
