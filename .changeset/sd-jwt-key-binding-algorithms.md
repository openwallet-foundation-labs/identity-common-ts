---
"@sd-jwt/core": minor
---

Add the `allowedKeyBindingAlgorithms` verifier option to restrict the algorithms of the Key Binding JWT. `allowedIssuerAlgorithms` only applies to issuer-signed JWTs, since the holder may use other algorithms than the issuer.
