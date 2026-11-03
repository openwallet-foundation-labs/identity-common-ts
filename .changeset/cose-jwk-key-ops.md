---
'@owf/cose': patch
---

`CoseKey.fromJwk` and `CoseKey.jwk` convert the JWK `key_ops` member (RFC 7517 Section 4.3). They used `keyOps` instead, so the key operations of a JWK were not converted, and the JWK of a COSE key had a `keyOps` member that JWK does not define. COSE `MAC create` and `MAC verify` (RFC 9052 Table 5) now become JWK `sign` and `verify` instead of `mACCreate` and `mACVerify`, and `sign` and `verify` of an `oct` JWK become `MAC create` and `MAC verify`.
