---
'@sd-jwt/sd-jwt-vc': patch
---

`SdJwtVcInstance.verify`, `safeVerify`, `validate` and `getVct` reject a JWT whose `typ` header is not `dc+sd-jwt` (SD-JWT VC draft 23, Section 2.2.1), with the code `INVALID_SD_JWT`. Before, they accepted any JWT signed with a key the verifier trusts as an SD-JWT VC, such as the Status List Token of the issuer. Credentials without `typ`, as issued with `omitTyp`, or with the `vc+sd-jwt` of earlier drafts are rejected too. `application/dc+sd-jwt` is accepted (RFC 7515 Section 4.1.9). `SdJwtVcInstance.issue` now refuses the `omitTyp` option, because the issuer MUST include `typ`.
