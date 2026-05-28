---
"@owf/cose": minor
---

Reworked the handling of algorithm name extraction:

- `alg` is only extracted from protected headers for Mac0 and Sign1
- No error is thrown when the alg cannot be extracted, since it's not a required parameter according to the COSE spec
- `algorithmName` on the Mac0 and Sign1 classes have been replaced by `algorithm` (COSE Algorithm identifier, number) and `jwaAlgorithm` (JOSE Algorithm identifier, string)
- `algorithm` is now provided to the verification methods in Sign1 and Mac0 context as optional parameter
- The `alg` parameter in `x509.getPublicKey` context method has been renamed to `algorithm` is now a COSE algorithm identifier, and optional due to `alg` not being required in Mac0 and Sign1 anymore.
