---
'@owf/identity-common': patch
'@owf/cose': minor
---

`@owf/identity-common` exports the zod helpers the packages share: `ValidationError`, `parseWithErrorHandling`, `parseWithZod`, `formatZodError`, `zodErrorMap`, `zNumericDate` and `BaseSchema`.

BREAKING: `@owf/cose` no longer exports `ValidationError` and throws the `ValidationError` of `@owf/identity-common` instead, which extends `IdentityError`: import it from there. `@owf/cose` also no longer configures zod globally with `z.config` when it is imported.
