---
'@owf/identity-common': minor
'@openid4vc/oauth2': minor
'@openid4vc/openid4vp': patch
---

`IdentityError` and `Oauth2Error` take a `sensitive` option for values that must not end up in logs, such as an expected `state`. They are kept on `error.sensitive`, which is not enumerable, so they are left out of the message and of a serialized or logged error. Call `setIdentityCommonConfig({ includeSensitiveErrorDetails: true })` to add them to the message, for example in tests or for debugging.

The `state` mismatch error of `validateOpenid4vpAuthorizationResponsePayload` no longer puts the expected and received `state` in its message, but passes them as `sensitive`.
