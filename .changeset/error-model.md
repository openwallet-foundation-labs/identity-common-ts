---
'@openid4vc/oauth2': minor
'@openid4vc/openid4vci': minor
'@openid4vc/utils': patch
---

BREAKING: `Oauth2Error`, `Openid4vciError` and `Openid4vcBaseError` extend `IdentityError` of `@owf/identity-common` instead of `Error`, so they can be caught together with the `@owf/jose` errors. The errors are named after their class, where `error.name` was `Error`, and `Oauth2Error` and `Openid4vciError` no longer append the message of their `cause` to their own message: read it from `cause`.
