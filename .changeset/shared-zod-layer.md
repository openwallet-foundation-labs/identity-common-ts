---
'@owf/identity-common': patch
'@owf/cose': minor
---

`@owf/identity-common` exports `ValidationError`, which carries the validation `issues` of a value that does not validate, and `parseWithErrorHandling`, which parses with a zod schema and throws it. It also exports `zNumericDate`, `BaseSchema` and `zodErrorMap`, an error map to pass per parse. `parseWithSchema` without `codes` gives a custom issue that has no code `invalid_value` instead of throwing. With it, the messages of zod leave out their prefix, e.g. `Invalid input:`, as the code says it. An issue can have `pathLabels`, the path as a reader knows it, which the message of a validation error shows. The schema code `missing` is now `missing_value`, with the `expected` value as context. A union that no member matches has the issues of each member as `branches`, and a discriminated union the allowed discriminator values.

BREAKING: `@owf/cose` no longer exports `ValidationError` and throws the `ValidationError` of `@owf/identity-common` instead. Its `issues` replace `zodError`, and its message lists them as `path: message`. Its issues have the CBOR keys as `path` and their names as `pathLabels`, and the unexpected keys of a map are one `unrecognized_keys` issue at the map, as zod reports them for an object. `@owf/cose` also no longer configures zod globally with `z.config` when it is imported, and no longer depends on `zod-validation-error`.
