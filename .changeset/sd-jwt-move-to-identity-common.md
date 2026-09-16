---
'@sd-jwt/core': minor
'@sd-jwt/sd-jwt-vc': minor
---

Move `@sd-jwt/core` and `@sd-jwt/sd-jwt-vc` from the `sd-jwt-js` repository into `identity-common-ts`. The `@sd-jwt/*` packages keep their own version line, separate from `@owf/*`.

The packages are now built with `tsdown`, like the other packages in this repository. The CommonJS entrypoint is `dist/index.cjs` (was `dist/index.js`), type declarations are exposed through the `types` export condition, and `@owf/*` dependencies use a caret range (`^`).
