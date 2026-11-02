---
"@openid4vc/openid4vci": patch
---

Send the `credential_response_encryption` `alg` where the issuer's version expects it: inside the `jwk` for OpenID4VCI 1.0, and next to the `jwk` for draft 14/15. The client now fails before sending the request if neither the `jwk` nor the request has an `alg`.
