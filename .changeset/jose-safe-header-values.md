---
'@owf/jose': patch
---

The errors of `assertKeyAllowedForSignatureAlgorithm` and `jwaSignatureAlgorithmsToCoseAlgorithms` escape the control characters of the `alg`, `use`, `key_ops`, `kty` and `crv` they name, and cut them off after 200 characters, with `errorMessageValue` of `@owf/identity-common`. These values come from the token, e.g. the `jwk` header of a DPoP proof, so they can no longer start a line of their own in a log.
