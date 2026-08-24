---
'@owf/eudi-attestation-schema': minor
---

Align generated DCQL claims paths with the claims path pointer definition: a non-empty array of strings, `null`s and non-negative integers.

Tuple-typed array schemas (`prefixItems`, or the array form of `items`) now yield one claim per position addressed by its non-negative index, instead of a single path for the array field. The claims path types `DcqlClaim`, `DcqlClaimsPath` and `DcqlClaimsPathComponent` are exported.
