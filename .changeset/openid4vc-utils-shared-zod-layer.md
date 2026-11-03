---
'@openid4vc/utils': minor
'@openid4vc/oauth2': minor
'@openid4vc/openid4vci': minor
'@openid4vc/openid4vp': minor
---

**Breaking:** `@openid4vc/utils` drops its copies of the `@owf/identity-common` helpers, `ValidationError`, `zNumericDate` and its `buffer` dependency:

| Removed from `@openid4vc/utils` | Use from `@owf/identity-common` |
| --- | --- |
| `decodeUtf8String`, `encodeToUtf8String` | `stringToBytes`, `bytesToString` |
| `encodeToBase64Url`, `encodeToBase64` | `base64url.encode`, `base64.encode` |
| `decodeBase64` | `base64.decode` or `base64url.decode` |
| `dateToSeconds` | `dateToSeconds` |
| `OrPromise`, `isJwtTyp`, `zTyp`, `parseWithErrorHandling`, `BaseSchema`, `ValidationError`, `zNumericDate` | the same names |

**Breaking:** the `@openid4vc` packages throw the `ValidationError` of `@owf/identity-common`, with `issues` instead of `zodError`. `formatZodError` is removed. The `result` of a `ZodFetcher` and the `*Result` fields of the `@openid4vc/openid4vci` responses are a `SchemaParseResult` with `issues`.

The packages no longer call `z.config` on import.
