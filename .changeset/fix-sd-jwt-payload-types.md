---
"@sd-jwt/core": patch
"@sd-jwt/sd-jwt-vc": patch
---

Propagate `ExtendedPayload` generic through `SDJwtInstance.decode`, `keys`, `presentableKeys`, and `getClaims`.
Add standard RFC 7519 `aud` and `jti` claims to `SdJwtVcPayload`.
