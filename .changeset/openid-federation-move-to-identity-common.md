---
'@owf/openid-federation': minor
---

Add `@owf/openid-federation`, previously published as `@openid-federation/core` from the `openid-federation-ts` repository. It is versioned together with the other `@owf/*` packages. Compared to `@openid-federation/core` 0.2.1, besides the changes listed separately:

- The schemas are `zod` 4 schemas. Schemas that keep unknown properties use `.loose()`.
- The package is ESM-only, like the other packages of this repository. Type declarations are exposed through the `types` export condition, and `require('@owf/openid-federation')` loads the ESM build, which needs a Node.js version that supports `require(esm)` (Node.js 20.19 and later, or 22.12 and later).
- The `buffer` dependency is removed, encoding uses `@owf/identity-common`. The header, payload and signature of a JWT must be base64url encoded, base64 is no longer accepted.
- Without a `fetchCallback`, `globalThis.fetch` is used, resolved on every request. Before, `global.fetch` was read, which is not defined in browsers.
- `base64ToBase64URL` and `hasMediaType` are removed. Use `base64url` and `isMediaType` from `@owf/identity-common`.
