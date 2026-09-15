---
'@owf/mdoc': minor
---

Move `@owf/mdoc` from the `mdoc-ts` repository into `identity-common-ts`. `@owf/mdoc` keeps its own version line, separate from the other `@owf/*` packages.

The package stays ESM-only. Type declarations are exposed through the `types` export condition, and `main` points to the ESM build. `require('@owf/mdoc')` loads the ESM build, which needs a Node.js version that supports `require(esm)` (Node.js 20.19 and later, or 22.12 and later). `@owf/*` dependencies use a caret range (`^`), and the `engines` field is removed.
