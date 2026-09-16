# @sd-jwt/core

## 0.21.0

### Minor Changes

- 65a7173: Move `@sd-jwt/core` and `@sd-jwt/sd-jwt-vc` from the `sd-jwt-js` repository into `identity-common-ts`. The `@sd-jwt/*` packages keep their own version line, separate from `@owf/*`.
  
  The packages are now built with `tsdown`, like the other packages in this repository. The CommonJS entrypoint is `dist/index.cjs` (was `dist/index.js`), type declarations are exposed through the `types` export condition, and `@owf/*` dependencies use a caret range (`^`).

### Patch Changes

- 65a7173: Add `base64urlDecodeJson` to `@owf/identity-common`, and use it in `decodeJwt`. Bytes that are not valid UTF-8 are now rejected instead of being decoded to a different string, and invalid base64url, UTF-8 or JSON in a JWT header or payload all throw `IdentityCommonException('Invalid JWT as input')`, without exposing parser details.
  
  `@sd-jwt/core` now uses these functions from `@owf/identity-common` for decoding JWTs and disclosures, instead of its own implementation. Errors are still thrown as `SDJWTException` with the same messages.
- Updated dependencies [b7e7f15]
- Updated dependencies [5934a14]
- Updated dependencies [65a7173]
- Updated dependencies [65a7173]
  - @owf/identity-common@0.4.0

## [0.20.1](https://github.com/openwallet-foundation/sd-jwt-js/compare/v0.20.0...v0.20.1) (2026-08-29)

### Bug Fixes

- update all deps ([#385](https://github.com/openwallet-foundation/sd-jwt-js/issues/385)) ([c95e1ab](https://github.com/openwallet-foundation/sd-jwt-js/commit/c95e1abfeb39c2814b874396cb03f1b7ef5d478c))

## [0.20.0](https://github.com/openwallet-foundation/sd-jwt-js/compare/v0.1.0...v0.20.0) (2026-06-29)

### Features

- version fixing to current 0.19.0 ([#382](https://github.com/openwallet-foundation/sd-jwt-js/issues/382)) ([d88c631](https://github.com/openwallet-foundation/sd-jwt-js/commit/d88c631fe4c3cefcbc96f268cb9d340296facbba))

## [0.1.0](https://github.com/openwallet-foundation/sd-jwt-js/compare/v0.19.0...v0.1.0) (2026-06-29)

### Bug Fixes

- **core:** reject tampered/unreferenced disclosures and reserved claims ([#380](https://github.com/openwallet-foundation/sd-jwt-js/issues/380)) ([3d8a72a](https://github.com/openwallet-foundation/sd-jwt-js/commit/3d8a72a0a279d67439db038c9c2b52621568b866))
- verify common jwt claims for kb-jwt ([#378](https://github.com/openwallet-foundation/sd-jwt-js/issues/378)) ([9e9bca1](https://github.com/openwallet-foundation/sd-jwt-js/commit/9e9bca10de3ad8574bfcbc875c85e37cee541505))

### Features

- allow disabling status verification ([#381](https://github.com/openwallet-foundation/sd-jwt-js/issues/381)) ([c9d73e4](https://github.com/openwallet-foundation/sd-jwt-js/commit/c9d73e4db2a925e5096988fffe7eded62db1b6a7))
