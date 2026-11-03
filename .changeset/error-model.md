---
'@openid4vc/oauth2': minor
'@openid4vc/openid4vci': minor
'@openid4vc/utils': minor
---

**Breaking:** `Oauth2Error`, `Openid4vciError` and `Openid4vcBaseError` extend `IdentityError` of `@owf/identity-common`. Their `name` is their class name. `Oauth2Error` and `Openid4vciError` no longer append the message of their `cause`.
