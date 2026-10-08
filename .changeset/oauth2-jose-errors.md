---
'@openid4vc/oauth2': minor
---

BREAKING: `Oauth2JwtParseError` and `Oauth2JwtVerificationError` are removed: use `JoseParseError` and `JoseVerificationError` (and its subclasses, such as `JoseSignatureVerificationError` and `JoseClaimVerificationError`), which `@openid4vc/oauth2` exports. A JWT whose header or payload does not match its schema raises a `JoseValidationError`, a subclass of `JoseParseError`, instead of a `ValidationError`. The `@owf/jose` errors do not extend `Oauth2Error`: catch `IdentityError` of `@owf/identity-common` to handle both.

Fixed: a DPoP proof whose header or payload does not match its schema, or whose `jwk` has no computable thumbprint, is rejected with an `invalid_dpop_proof` error response instead of throwing a `ValidationError`.
