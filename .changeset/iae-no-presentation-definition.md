---
"@openid4vc/openid4vp": patch
---

`parseOpenid4vpAuthorizationRequest` rejects an Interactive Authorization Endpoint request (`iae_post`, `iae_post.jwt`) that has a `presentation_definition`. These requests only support `dcql_query`. Before, the parameter was ignored.
