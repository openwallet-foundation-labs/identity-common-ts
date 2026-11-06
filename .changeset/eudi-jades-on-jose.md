---
'@owf/eudi-jades': minor
---

Built on `@owf/jose`: `signJades`, `verifyJades`, `verifyJadesJwt` and `decodeJades` replace `Token` and the `verify*` and `decode` functions.

**Breaking:** use these functions with the `@owf/jose` callbacks. A signature that does not meet ETSI TS 119 182-1 throws a `JadesValidationError` with coded `issues`, which `validateProfile` now returns instead of `missing`. A string `jws` is read as a compact serialization, so pass a JSON serialization as an object. `decodeJades` checks the B-B profile unless `profile` says otherwise.
