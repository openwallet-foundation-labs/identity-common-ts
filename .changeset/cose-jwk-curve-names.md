---
"@owf/cose": patch
---

Use the registered JWK `crv` names `P-384` and `P-521`. `fromJwk` now accepts these values, and `.jwk` emits them instead of `p-384` and `p-521`.
