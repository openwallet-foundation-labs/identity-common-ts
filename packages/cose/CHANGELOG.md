# @owf/cose

## 0.3.2

### Patch Changes

- @owf/identity-common@0.3.2

## 0.3.1

### Patch Changes

- @owf/identity-common@0.3.1

## 0.3.0

### Minor Changes

- 4bd7eb7: fix: correctly handle detached payload vs payload on sign1 and mac0. The detached payload is not available on the Sign1 and Mac0 classes anymore, and should be provided to the method classes directly. Detached payload cannot be provided anymore when embedded payload is already present. The `mac0` and `sign1` structures are not passed anymore to the context, but the already encoded data is provided.
- dad635c: refactor: only allow CoseKey as return value for getPublicKey in x509 context
- 6309c48: Reworked the handling of algorithm name extraction:

  - `alg` is only extracted from protected headers for Mac0 and Sign1
  - No error is thrown when the alg cannot be extracted, since it's not a required parameter according to the COSE spec
  - `algorithmName` on the Mac0 and Sign1 classes have been replaced by `algorithm` (COSE Algorithm identifier, number) and `jwaAlgorithm` (JOSE Algorithm identifier, string)
  - `algorithm` is now provided to the verification methods in Sign1 and Mac0 context as optional parameter
  - The `alg` parameter in `x509.getPublicKey` context method has been renamed to `algorithm` is now a COSE algorithm identifier, and optional due to `alg` not being required in Mac0 and Sign1 anymore.

- dad635c: refactor: only allow CosKey for sign1.verify
- 353df0c: fix: do now allow array of certificates in x509 context
- 353df0c: refactor: rename Mac0Context 'mac' method to 'authenticate'
- 2b0eeaf: Type the known COSE header claims. `kid` (label 4) is now validated as a bstr when decoding protected and unprotected headers, so a malformed `{ 4: undefined }` is rejected for every `Sign1`-derived structure (e.g. a `deviceSignature`) instead of being silently accepted. The other registered labels are enumerated as known keys; additional/private-use labels still pass through. `ProtectedHeaders`/`UnprotectedHeaders` now back their structure with a `TypedMap`, and the `.headers` accessor keeps `kid` typed as a bstr while allowing access to any other integer label.

### Patch Changes

- f1f42db: - cosekey algorithm now also can be MacAlgorithm
  - Some support for ed25519 to get the public and private key
- 353df0c: feat: add status list info objects for referenced status list token
- Updated dependencies [353df0c]
  - @owf/identity-common@0.3.0

## 0.2.0

### Patch Changes

- b79d4ba: align package json for export
- Updated dependencies [b79d4ba]
- Updated dependencies [7ef6497]
- Updated dependencies [f50ec6e]
- Updated dependencies [293e5ec]
  - @owf/identity-common@0.2.0
