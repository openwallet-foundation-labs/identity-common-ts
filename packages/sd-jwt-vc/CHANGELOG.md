# @sd-jwt/sd-jwt-vc

## 0.22.0

### Minor Changes

- 1dd14dc: Pass the verification options to the status list verifier again, e.g. to resolve the key of the status list issuer. Only the time options are applied to the claims of the Status List Token.
  
  `SDJwtVcInstance` and `SDJWTVCConfig` now take the custom verification options as type parameter, like `SDJwtInstance` does, so the options passed to the `verifier` and the `statusVerifier` are typed: `new SDJwtVcInstance<{ statusListKey: KeyObject }>({ statusVerifier: (data, sig, options) => ... })`.

### Patch Changes

- b020b40: `safeVerify` now takes the error code from the `code` set on `SDJWTException` where the error is thrown, instead of matching substrings of the error message. Errors without a code (such as errors thrown by a custom verifier callback) are reported as `UNKNOWN_ERROR`.
  
  **Breaking:** the `SDJWTException` constructor takes an options object instead of positional arguments: `new SDJWTException(message, { details, code, cause })`. Replace `new SDJWTException(message, details)` with `new SDJWTException(message, { details })`. `JwtTimeClaimException` takes the same options, with `details` and `code` required.
  
  In `@sd-jwt/sd-jwt-vc`, `safeVerify` keeps the code of an `SDJWTException` thrown during the status and type metadata checks, for example `STATUS_INVALID` from a custom `statusValidator`, and only falls back to `STATUS_VERIFICATION_FAILED` or `VCT_VERIFICATION_FAILED` for errors without a code.
- 1cd910e: Scope `expectedIssuer`, `expectedSubject`, `expectedVct`, and `maxAgeSeconds` to the issuer-signed SD-JWT payload rather than applying them to the Key Binding JWT or Status List Token. Credential `expectedAudience` and `allowedIssuerAlgorithms` no longer constrain the Key Binding JWT. Use `expectedKeyBindingAudience` to constrain the Key Binding JWT's audience. Issuer algorithm restrictions no longer constrain the Status List Token and its signature remains verified by the configured status verifier.
- f599719: Verify the `typ` header of a Status List Token in JWT format. Token Status List requires the header to be `statuslist+jwt`, and requires a relying party to check it. `application/statuslist+jwt` is accepted too, as RFC 7515 section 4.1.9 requires of a recipient.
  
  - `@owf/token-status-list`: new `verifyStatusListJwtHeader`, which `verifyStatus` now calls before the claims.
  - `@sd-jwt/sd-jwt-vc`: `verify` and `safeVerify` reject a status list token with a missing or wrong `typ` header, before its signature is verified.
- 3b15c07: Expose the values behind failed time and status checks on the thrown exceptions, so callers can tell clock drift apart from an expired or stale token without parsing messages.
  
  - `@sd-jwt/core`: a failed `iat`, `nbf`, `exp` or maximum age check throws a `JwtTimeClaimException` (a subclass of `SDJWTException`). Its `details` (`JwtTimeClaimErrorDetails`) hold the claim, its value, the current time, the allowed clock skew and, for the maximum age check, the maximum age. `SDJWTException` has a new optional `code`, here `JWT_EXPIRED`, `JWT_NOT_YET_VALID` or `JWT_TOO_OLD`; `safeVerify` uses it before falling back to message matching.
  - `@sd-jwt/core`: time check failures of the Key Binding JWT say `Key Binding JWT` instead of `JWT` and carry the new codes `KEY_BINDING_JWT_EXPIRED`, `KEY_BINDING_JWT_NOT_YET_VALID` and `KEY_BINDING_JWT_TOO_OLD`. `safeVerify` reports these codes instead of `KEY_BINDING_SIGNATURE_INVALID`.
  - `@sd-jwt/sd-jwt-vc`: when the status list token fails verification, the `SLException` has the status list URI in `details` and the original exception as `cause`. A credential whose status is not valid fails with code `STATUS_INVALID` and `details` `{ uri, idx, status }`. A custom `statusValidator` receives the URI and index as a second argument.
  - `@owf/mdoc`: the reason of the MSO validity check includes the MSO's validity period and the allowed clock skew.
- Updated dependencies [1dd14dc]
- Updated dependencies [b020b40]
- Updated dependencies [1cd910e]
- Updated dependencies [f599719]
- Updated dependencies [f2aaf3e]
- Updated dependencies [3b15c07]
  - @sd-jwt/core@0.22.0
  - @owf/token-status-list@0.4.2
  - @owf/identity-common@0.4.2

## 0.21.1

### Patch Changes

- a7b5b83: Propagate `ExtendedPayload` generic through `SDJwtInstance.decode`, `keys`, `presentableKeys`, and `getClaims`.
  Add standard RFC 7519 `aud` and `jti` claims to `SdJwtVcPayload`.
- Updated dependencies [833bfbc]
- Updated dependencies [a7b5b83]
  - @sd-jwt/core@0.21.1
  - @owf/identity-common@0.4.1
  - @owf/token-status-list@0.4.1

## 0.21.0

### Minor Changes

- 65a7173: Move `@sd-jwt/core` and `@sd-jwt/sd-jwt-vc` from the `sd-jwt-js` repository into `identity-common-ts`. The `@sd-jwt/*` packages keep their own version line, separate from `@owf/*`.
  
  The packages are now built with `tsdown`, like the other packages in this repository. The CommonJS entrypoint is `dist/index.cjs` (was `dist/index.js`), type declarations are exposed through the `types` export condition, and `@owf/*` dependencies use a caret range (`^`).
- 65a7173: Verify the claims of the Status List Token with `verifyStatusListJwtClaims` from `@owf/token-status-list`. `sub` and `iat` are now required, and `sub` has to match the `uri` of the status list reference. The `currentDate` and `skewSeconds` verifier options are applied to these checks.
  
  The default status list fetcher now compares the `Content-Type` header with `isMediaType`, so a response such as `application/statuslist+jwt; charset=utf-8` is accepted.
  
  Fixes: the status list JWT is verified with `verifier` when no `statusVerifier` is configured, instead of failing with `Verifier not found for status list JWT`.

### Patch Changes

- Updated dependencies [b7e7f15]
- Updated dependencies [e40f6a2]
- Updated dependencies [65a7173]
- Updated dependencies [5934a14]
- Updated dependencies [c55b5d0]
- Updated dependencies [019050d]
- Updated dependencies [0cd489f]
- Updated dependencies [65a7173]
- Updated dependencies [1aa5cb6]
- Updated dependencies [65a7173]
- Updated dependencies [46a42a3]
- Updated dependencies [46a42a3]
- Updated dependencies [65a7173]
  - @owf/identity-common@0.4.0
  - @owf/token-status-list@0.4.0
  - @sd-jwt/core@0.21.0

## [0.20.1](https://github.com/openwallet-foundation/sd-jwt-js/compare/v0.20.0...v0.20.1) (2026-08-29)

### Bug Fixes

- update all deps ([#385](https://github.com/openwallet-foundation/sd-jwt-js/issues/385)) ([c95e1ab](https://github.com/openwallet-foundation/sd-jwt-js/commit/c95e1abfeb39c2814b874396cb03f1b7ef5d478c))

## [0.20.0](https://github.com/openwallet-foundation/sd-jwt-js/compare/v0.1.0...v0.20.0) (2026-06-29)

### Features

- version fixing to current 0.19.0 ([#382](https://github.com/openwallet-foundation/sd-jwt-js/issues/382)) ([d88c631](https://github.com/openwallet-foundation/sd-jwt-js/commit/d88c631fe4c3cefcbc96f268cb9d340296facbba))

## [0.1.0](https://github.com/openwallet-foundation/sd-jwt-js/compare/v0.19.0...v0.1.0) (2026-06-29)

### Bug Fixes

- **core:** reject tampered/unreferenced disclosures and reserved claims ([#380](https://github.com/openwallet-foundation/sd-jwt-js/issues/380)) ([3d8a72a](https://github.com/openwallet-foundation/sd-jwt-js/commit/3d8a72a0a279d67439db038c9c2b52621568b866))
- **sd-jwt-vc:** config param type override in SDJwtVcInstance ([#379](https://github.com/openwallet-foundation/sd-jwt-js/issues/379)) ([fe18c35](https://github.com/openwallet-foundation/sd-jwt-js/commit/fe18c3572055c3307d05f43f738c1d3c3f15de38))

### Features

- allow disabling status verification ([#381](https://github.com/openwallet-foundation/sd-jwt-js/issues/381)) ([c9d73e4](https://github.com/openwallet-foundation/sd-jwt-js/commit/c9d73e4db2a925e5096988fffe7eded62db1b6a7))
