---
'@sd-jwt/core': patch
'@sd-jwt/sd-jwt-vc': patch
---

Verification now rejects an issuer-signed JWT or Key Binding JWT whose header has `crit`, as RFC 7515 requires for extensions the verifier does not understand, and an SD-JWT VC in which a protected claim (`iss`, `nbf`, `exp`, `cnf`, `vct`, `vct#integrity` or `status`) arrived in a Disclosure.
