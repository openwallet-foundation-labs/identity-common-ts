---
"@sd-jwt/core": patch
"@sd-jwt/sd-jwt-vc": patch
---

Scope `expectedIssuer`, `expectedSubject`, `expectedVct`, and `maxAgeSeconds` to the issuer-signed SD-JWT payload rather than applying them to the Key Binding JWT or Status List Token. Credential `expectedAudience` and `allowedIssuerAlgorithms` no longer constrain the Key Binding JWT. Use `expectedKeyBindingAudience` to constrain the Key Binding JWT's audience. Issuer algorithm restrictions no longer constrain the Status List Token and its signature remains verified by the configured status verifier.
