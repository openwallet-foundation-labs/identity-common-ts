---
'@sd-jwt/sd-jwt-vc': minor
---

Verify the claims of the Status List Token with `verifyStatusListJwtClaims` from `@owf/token-status-list`. `sub` and `iat` are now required, and `sub` has to match the `uri` of the status list reference. The `currentDate` and `skewSeconds` verifier options are applied to these checks.

The default status list fetcher now compares the `Content-Type` header with `isMediaType`, so a response such as `application/statuslist+jwt; charset=utf-8` is accepted.

Fixes: the status list JWT is verified with `verifier` when no `statusVerifier` is configured, instead of failing with `Verifier not found for status list JWT`.
