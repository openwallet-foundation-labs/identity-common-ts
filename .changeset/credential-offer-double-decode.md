---
'@openid4vc/openid4vci': patch
---

`resolveCredentialOffer` no longer percent-decodes the `credential_offer` query parameter a second time (OpenID4VCI 1.0 Section 4.1). An offer whose JSON contains a literal `%` failed to parse, and a value such as `%2F` was changed to `/`.
