---
'@openid4vc/oauth2': minor
'@openid4vc/openid4vci': minor
'@openid4vc/openid4vp': minor
---

Every JWT verification takes `now` and `allowedSkewInSeconds` (30 seconds by default), and `Oauth2ResourceServer`, `Openid4vciIssuer`, `Openid4vciClient`, `Openid4vpClient` and `Openid4vpVerifier` take a default `allowedSkewInSeconds`. Key attestations and JAR request objects are verified at the `now` passed in.

DPoP proofs: `maxProofAgeSeconds` allows the skew, an `iat` in the future is always rejected, `assertJtiUniqueness` runs after the signature check, and the `JoseValidationError` of a failed claim is the `cause` of the error response.

A `JoseInvalidArgumentError`, e.g. for a negative skew, is thrown as is instead of as an error response. An expired OpenID4VP request object gives `invalid_request_object`.

A `typ` is accepted in any casing and with the `application/` prefix (RFC 7515 Section 4.1.9). Compare it with `isJwtTyp` of `@owf/identity-common`.
