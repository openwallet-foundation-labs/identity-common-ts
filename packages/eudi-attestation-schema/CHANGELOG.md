# @owf/eudi-attestation-schema

## 0.4.0

### Minor Changes

- d055426: Align generated DCQL claims paths with the claims path pointer definition: a non-empty array of strings, `null`s and non-negative integers.
  
  Tuple-typed array schemas (a non-empty `prefixItems`, or the array form of `items`) now yield one claim per position addressed by its non-negative index, instead of a single path for the array field. A rest schema next to those positions (`items` alongside `prefixItems`, or `additionalItems`) is skipped, since a claims path pointer cannot address every index from a position onwards. The claims path types `DcqlClaim`, `DcqlClaimsPath` and `DcqlClaimsPathComponent` are exported.
  
  Fix claim extraction dropping a sub-schema that is shared between sibling properties by object identity, which can happen when a schema is resolved as an already-parsed object. Cycle detection is now scoped to the current branch instead of the whole traversal, so a shared sub-schema yields claims at every path it appears under.

### Patch Changes

- Updated dependencies [b7e7f15]
- Updated dependencies [5934a14]
  - @owf/identity-common@0.4.0
  - @owf/crypto@0.4.0

## 0.3.2

### Patch Changes

- 6aa8acc: update readme
- a7eb841: remove node api usage
  - @owf/crypto@0.3.2
  - @owf/identity-common@0.3.2

## 0.3.1

### Patch Changes

- @owf/crypto@0.3.1
- @owf/identity-common@0.3.1

## 0.3.0

### Patch Changes

- Updated dependencies [353df0c]
  - @owf/identity-common@0.3.0
  - @owf/crypto@0.3.0

## 0.2.0

### Minor Changes

- 6bd9c63: add package for attestation schema handling for rulebooks

### Patch Changes

- 81371c5: remove redundant format info
- b79d4ba: align package json for export
- 293e5ec: Also include commonjs builds
- Updated dependencies [b79d4ba]
- Updated dependencies [7ef6497]
- Updated dependencies [f50ec6e]
- Updated dependencies [293e5ec]
- Updated dependencies [6bd9c63]
  - @owf/identity-common@0.2.0
  - @owf/crypto@0.2.0

## 0.1.0

### Patch Changes

- Updated dependencies [7ef6497]
- Updated dependencies [f50ec6e]
  - @owf/identity-common@0.1.0
  - @owf/crypto@0.1.0
