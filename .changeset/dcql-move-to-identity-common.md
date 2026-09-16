---
'dcql': patch
---

Move `dcql` from the `dcql-ts` repository into `identity-common-ts`. `dcql` keeps its own version line, separate from the other packages in this repository.

The package stays ESM-only. Type declarations are exposed through the `types` export condition, and `main` points to the ESM build. `require('dcql')` loads the ESM build, which needs a Node.js version that supports `require(esm)` (Node.js 20.19 and later, or 22.12 and later).
