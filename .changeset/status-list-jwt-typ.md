---
"@owf/token-status-list": patch
"@sd-jwt/sd-jwt-vc": patch
---

Verify the `typ` header of a Status List Token in JWT format. Token Status List requires the header to be `statuslist+jwt`, and requires a relying party to check it. `application/statuslist+jwt` is accepted too, as RFC 7515 section 4.1.9 requires of a recipient.

- `@owf/token-status-list`: new `verifyStatusListJwtHeader`, which `verifyStatus` now calls before the claims.
- `@sd-jwt/sd-jwt-vc`: `verify` and `safeVerify` reject a status list token with a missing or wrong `typ` header, before its signature is verified.
