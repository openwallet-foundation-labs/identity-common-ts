---
"@openid4vc/oauth2": minor
---

BREAKING: `parseJarRequest` and `validateJarRequestParams` no longer allow a `request_uri` by default. The `allowRequestUri` option now defaults to `false`, so a JAR request passed by reference is rejected with an `invalid_request_object` error (and `parseJarRequest` won't fetch it) unless you explicitly pass `allowRequestUri: true`.
