---
'@openid4vc/utils': minor
'@openid4vc/oauth2': minor
'@openid4vc/openid4vci': minor
'@openid4vc/openid4vp': minor
---

BREAKING: `@openid4vc/utils` no longer exports `ValidationError`, `formatZodError` and `zNumericDate`: import them from `@owf/identity-common`. The `@openid4vc` packages throw the `ValidationError` of `@owf/identity-common`, which extends `IdentityError` rather than `Openid4vcBaseError`, and the default message of `parseWithErrorHandling` no longer includes the data that failed to validate.

The `@openid4vc` packages no longer configure zod globally with `z.config` when they are imported.
