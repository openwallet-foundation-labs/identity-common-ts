# @sd-jwt/core

## 0.22.0

### Minor Changes

- 1dd14dc: Add the `allowedKeyBindingAlgorithms` verifier option to restrict the algorithms of the Key Binding JWT. `allowedIssuerAlgorithms` only applies to issuer-signed JWTs, since the holder may use other algorithms than the issuer.
- b020b40: `safeVerify` now takes the error code from the `code` set on `SDJWTException` where the error is thrown, instead of matching substrings of the error message. Errors without a code (such as errors thrown by a custom verifier callback) are reported as `UNKNOWN_ERROR`.
  
  **Breaking:** the `SDJWTException` constructor takes an options object instead of positional arguments: `new SDJWTException(message, { details, code, cause })`. Replace `new SDJWTException(message, details)` with `new SDJWTException(message, { details })`. `JwtTimeClaimException` takes the same options, with `details` and `code` required.
  
  In `@sd-jwt/sd-jwt-vc`, `safeVerify` keeps the code of an `SDJWTException` thrown during the status and type metadata checks, for example `STATUS_INVALID` from a custom `statusValidator`, and only falls back to `STATUS_VERIFICATION_FAILED` or `VCT_VERIFICATION_FAILED` for errors without a code.

### Patch Changes

- 1cd910e: Scope `expectedIssuer`, `expectedSubject`, `expectedVct`, and `maxAgeSeconds` to the issuer-signed SD-JWT payload rather than applying them to the Key Binding JWT or Status List Token. Credential `expectedAudience` and `allowedIssuerAlgorithms` no longer constrain the Key Binding JWT. Use `expectedKeyBindingAudience` to constrain the Key Binding JWT's audience. Issuer algorithm restrictions no longer constrain the Status List Token and its signature remains verified by the configured status verifier.
- 3b15c07: Expose the values behind failed time and status checks on the thrown exceptions, so callers can tell clock drift apart from an expired or stale token without parsing messages.
  
  - `@sd-jwt/core`: a failed `iat`, `nbf`, `exp` or maximum age check throws a `JwtTimeClaimException` (a subclass of `SDJWTException`). Its `details` (`JwtTimeClaimErrorDetails`) hold the claim, its value, the current time, the allowed clock skew and, for the maximum age check, the maximum age. `SDJWTException` has a new optional `code`, here `JWT_EXPIRED`, `JWT_NOT_YET_VALID` or `JWT_TOO_OLD`; `safeVerify` uses it before falling back to message matching.
  - `@sd-jwt/core`: time check failures of the Key Binding JWT say `Key Binding JWT` instead of `JWT` and carry the new codes `KEY_BINDING_JWT_EXPIRED`, `KEY_BINDING_JWT_NOT_YET_VALID` and `KEY_BINDING_JWT_TOO_OLD`. `safeVerify` reports these codes instead of `KEY_BINDING_SIGNATURE_INVALID`.
  - `@sd-jwt/sd-jwt-vc`: when the status list token fails verification, the `SLException` has the status list URI in `details` and the original exception as `cause`. A credential whose status is not valid fails with code `STATUS_INVALID` and `details` `{ uri, idx, status }`. A custom `statusValidator` receives the URI and index as a second argument.
  - `@owf/mdoc`: the reason of the MSO validity check includes the MSO's validity period and the allowed clock skew.
- @owf/identity-common@0.4.2

## 0.21.1

### Patch Changes

- 833bfbc: Fix nested disclosure value mutation during `unpack` by cloning disclosure values before recursive unpacking.
- a7b5b83: Propagate `ExtendedPayload` generic through `SDJwtInstance.decode`, `keys`, `presentableKeys`, and `getClaims`.
  Add standard RFC 7519 `aud` and `jti` claims to `SdJwtVcPayload`.
- @owf/identity-common@0.4.1

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
