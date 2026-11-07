---
'@owf/jose': minor
---

BREAKING: `signCompactJws` and `signJwt` reject a header whose `kid`, `x5c`, `jwk` or `trust_chain` contradicts the signer, or that also identifies a signer of another method, such as a `jwk` next to the `x5c` of an `x5c` signer. `jwsSignerFromHeader` would establish another signer from such a header. A header that leaves the signer's parameters out is still signed.
