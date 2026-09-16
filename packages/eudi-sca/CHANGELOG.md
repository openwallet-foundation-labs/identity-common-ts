# @owf/eudi-sca

## 0.4.0

### Patch Changes

- 83900b6: Depend on `@owf/mdoc` from this repository. `createMdocDeviceResponse` now adds the SCA device namespace with `DeviceNamespaces.setDeviceNamespace`, so the namespace is also encoded when the device namespaces of the mdoc were decoded, as `@owf/mdoc` encodes decoded structures with the bytes they were received as until they are modified.
- edfc2b5: Depend on `@openid4vc/openid4vci` from this repository.
- 65a7173: Depend on `@sd-jwt/core` from this repository, and take the `Signer` type from `@owf/identity-common` instead of the deprecated `@sd-jwt/types` package.
- 65a7173: Build all base64, base64url, UTF-8 and JSON encoding on a single implementation in `@owf/identity-common`.
  
  - `base64` and `base64url` share one codec. Decoding input with an impossible length (a single trailing character) now throws instead of returning a corrupt byte.
  - `stringToBytes` and `bytesToString` use `TextEncoder` and `TextDecoder`, which must now be available in the environment (see the React Native notes in the README). `bytesToString` and `base64urlDecode` accept `{ fatal: true }` to throw on invalid UTF-8 instead of replacing it.
  - `base64urlDecodeJson` and `decodeJwt` build on these layers.
  
  `@owf/crypto`, `@owf/eudi-jades`, `@owf/eudi-sca` and `@owf/token-status-list` use these functions instead of their own `TextEncoder`, `TextDecoder` and `JSON.parse` calls. JSON decoded from base64url (JAdES headers and `etsiU` values, transaction data, and status list token payloads) is now strict about UTF-8.
- Updated dependencies [83900b6]
- Updated dependencies [83900b6]
- Updated dependencies [b7e7f15]
- Updated dependencies [83900b6]
- Updated dependencies [83900b6]
- Updated dependencies [83900b6]
- Updated dependencies [83900b6]
- Updated dependencies [83900b6]
- Updated dependencies [83900b6]
- Updated dependencies [83900b6]
- Updated dependencies [83900b6]
- Updated dependencies [83900b6]
- Updated dependencies [5934a14]
- Updated dependencies [83900b6]
- Updated dependencies [83900b6]
- Updated dependencies [83900b6]
- Updated dependencies [83900b6]
- Updated dependencies [83900b6]
- Updated dependencies [83900b6]
- Updated dependencies [edfc2b5]
- Updated dependencies [83900b6]
- Updated dependencies [83900b6]
- Updated dependencies [83900b6]
- Updated dependencies [83900b6]
- Updated dependencies [83900b6]
- Updated dependencies [65a7173]
- Updated dependencies [83900b6]
- Updated dependencies [65a7173]
- Updated dependencies [83900b6]
- Updated dependencies [65a7173]
- Updated dependencies [83900b6]
  - @owf/mdoc@0.8.0
  - @owf/identity-common@0.4.0
  - @openid4vc/openid4vci@0.5.6
  - @sd-jwt/core@0.21.0
  - @owf/crypto@0.4.0

## 0.3.2

### Patch Changes

- @owf/crypto@0.3.2
- @owf/identity-common@0.3.2

## 0.3.1

### Patch Changes

- @owf/crypto@0.3.1
- @owf/identity-common@0.3.1

## 0.3.0

### Minor Changes

- eff25c4: remove export from dependencies

### Patch Changes

- Updated dependencies [353df0c]
  - @owf/identity-common@0.3.0
  - @owf/crypto@0.3.0

## 0.2.0

### Patch Changes

- b79d4ba: align package json for export
- 4b5c1fc: fix index file for export
- 293e5ec: Also include commonjs builds
- Updated dependencies [b79d4ba]
- Updated dependencies [7ef6497]
- Updated dependencies [f50ec6e]
- Updated dependencies [293e5ec]
- Updated dependencies [6bd9c63]
  - @owf/identity-common@0.2.0
  - @owf/crypto@0.2.0
