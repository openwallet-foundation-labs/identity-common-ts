---
"@sd-jwt/sd-jwt-vc": minor
---

Pass the verification options to the status list verifier again, e.g. to resolve the key of the status list issuer. Only the time options are applied to the claims of the Status List Token.

`SDJwtVcInstance` and `SDJWTVCConfig` now take the custom verification options as type parameter, like `SDJwtInstance` does, so the options passed to the `verifier` and the `statusVerifier` are typed: `new SDJwtVcInstance<{ statusListKey: KeyObject }>({ statusVerifier: (data, sig, options) => ... })`.
