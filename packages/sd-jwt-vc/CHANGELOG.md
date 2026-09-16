# @sd-jwt/sd-jwt-vc

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
