---
'@owf/eudi-attestation-schema': minor
---

Align generated DCQL claims paths with the claims path pointer definition: a non-empty array of strings, `null`s and non-negative integers.

Tuple-typed array schemas (a non-empty `prefixItems`, or the array form of `items`) now yield one claim per position addressed by its non-negative index, instead of a single path for the array field. A rest schema next to those positions (`items` alongside `prefixItems`, or `additionalItems`) is skipped, since a claims path pointer cannot address every index from a position onwards. The claims path types `DcqlClaim`, `DcqlClaimsPath` and `DcqlClaimsPathComponent` are exported.

Fix claim extraction dropping a sub-schema that is shared between sibling properties by object identity, which can happen when a schema is resolved as an already-parsed object. Cycle detection is now scoped to the current branch instead of the whole traversal, so a shared sub-schema yields claims at every path it appears under.
