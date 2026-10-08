---
'@owf/eudi-wrprc': minor
'@owf/token-status-list': minor
'@sd-jwt/core': minor
'@sd-jwt/sd-jwt-vc': minor
---

BREAKING: identifiers are spelled `Jwt` rather than `JWT`, and the old names are removed:

| Package | Before | After |
| --- | --- | --- |
| `@sd-jwt/core` | `SDJWTException`, `SDJWTExceptionOptions` | `SDJwtException`, `SDJwtExceptionOptions` |
| `@sd-jwt/core` | `SDJWTConfig`, `SDJWTCompact` | `SDJwtConfig`, `SDJwtCompact` |
| `@sd-jwt/core` | `Jwt.decodeJWT` | `Jwt.decodeJwt` |
| `@sd-jwt/sd-jwt-vc` | `SDJWTVCConfig`, `SDJWTVCStatusReference` | `SDJwtVcConfig`, `SDJwtVcStatusReference` |
| `@owf/token-status-list` | `StatusListJWTPayload`, `StatusListJWTHeaderParameters` | `StatusListJwtPayload`, `StatusListJwtHeaderParameters` |
| `@owf/token-status-list` | `JWTwithStatusListPayload`, `JWTClaimNames` | `JwtWithStatusListPayload`, `JwtClaimNames` |
| `@owf/eudi-wrprc` | `WRPRCJWTHeader`, `WRPRCJWTHeaderSchema`, `validateWRPRCJWTHeader` | `WRPRCJwtHeader`, `WRPRCJwtHeaderSchema`, `validateWRPRCJwtHeader` |

The `name` of an `SDJwtException` changed with it, from `SDJWTException` to `SDJwtException`.
