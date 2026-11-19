---
'@sd-jwt/core': minor
'@sd-jwt/sd-jwt-vc': minor
---

Verifying and presenting an SD-JWT decodes it and hashes its disclosures once.

- `SdJwtInstance.verify`, `safeVerify`, `validate`, `present`, `keys`, `presentableKeys` and `getClaims` also accept the `SdJwt` that `decode` returned, next to the compact string. So do `verify`, `safeVerify`, `validate`, `verifyTypeMetadata` and `getVct` of `SdJwtVcInstance`. A subclass that overrides `validate` now receives an `SdJwt` from `verify`.
- `SdJwtInstance.issueSdJwt` issues like `issue` and returns the `SdJwt` with the signed JWT and its disclosures. `encodeSdJwt()` gives the compact form.
- `SdJwtVcInstance.getVct` accepts `verifyJwt: false` in its options, and then does not verify the issuer signature. Only set it for an SD-JWT-VC whose signature was verified before.
- `present` with a Key Binding JWT selects the disclosures once, and the Status List Token is decoded once.
- `Jwt.sign` serialises the header and payload once, and returns the token with the new signature when the `Jwt` was decoded from a signed token. Before, it returned the token it was decoded from.
