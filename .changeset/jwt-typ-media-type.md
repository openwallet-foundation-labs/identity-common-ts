---
'@openid4vc/utils': patch
'@openid4vc/oauth2': patch
'@openid4vc/openid4vci': patch
---

Accept the JWT `typ` header in its full media type form (`application/openid4vci-proof+jwt`) and in any casing, as RFC 7515 Section 4.1.9 requires. This applies to client attestations, client attestation PoPs, JAR request objects, access tokens, credential request proofs, key attestations and signed credential issuer metadata. Created JWTs still use the short lowercase form. `@openid4vc/utils` adds `isJwtTyp(value, typ)` for the check, and `zTyp(typ)`, a schema that uses it. It keeps `typ` as sent, so the `typ` of the parsed header types is now `string`.
