---
'@openid4vc/oauth2': minor
---

**Breaking:** `Oauth2JwtParseError` and `Oauth2JwtVerificationError` are removed. Catch the `@owf/jose` errors that `@openid4vc/oauth2` exports: `JoseParseError`, `JoseVerificationError` and its subclasses, and `JoseValidationError` for a header or claim that does not validate, with issue codes such as `invalid_typ`, `expired` or `claim_value_mismatch`. They don't extend `Oauth2Error`, so catch `IdentityError` to handle both.
