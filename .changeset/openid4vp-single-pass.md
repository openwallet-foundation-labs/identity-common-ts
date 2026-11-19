---
"@openid4vc/openid4vp": minor
---

`resolveOpenid4vpAuthorizationRequest` accepts the result of `parseOpenid4vpAuthorizationRequest` as `parsedAuthorizationRequest`, instead of `authorizationRequestPayload`. The request is then not parsed a second time. The new type `ParseOpenid4vpAuthorizationRequestResult` is that result.

A `dcql_query` or `presentation_definition` passed as a JSON string must decode to an object. `parseOpenid4vpAuthorizationRequest` now rejects any other value, where before only `resolveOpenid4vpAuthorizationRequest` did. A string that is JSON encoded twice is no longer accepted.

`verifyJarmAuthorizationResponse` returns the validated `header` of the response JWT. `parseOpenid4vpAuthorizationResponse` uses it and no longer decodes the header and matches the JARM claims a second time.
