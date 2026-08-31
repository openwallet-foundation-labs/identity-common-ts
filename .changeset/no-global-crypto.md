---
'@owf/token-status-list': minor
'@owf/eudi-jades': minor
---

**Breaking:** stop reaching for `globalThis.crypto`. Hashing now comes from a caller-supplied,
pluggable implementation, so consumers on runtimes without a global Web Crypto API — and consumers
that must route crypto through a reviewed or policy-constrained engine — are no longer forced to
patch the global.

- `@owf/token-status-list`: `createStatusListIndexAllocator` and `StatusListIndexAllocator.create` take
  `(options, ctx)` instead of positional arguments, where `options` is `{ length, seed, position? }` and
  `ctx` is `{ hasher }`. The hasher must compute SHA-256 for the permutation to stay reproducible.
  Persisted allocator state can be passed straight through: `StatusListIndexAllocator.create(state, ctx)`.
- `@owf/eudi-jades`: `Token.getHash` takes the hasher as its first argument —
  `getHash(hasher, algorithm?)`, e.g. `token.getHash(hasher)` with `hasher` from `@owf/crypto`.
