---
'@openid4vc/oauth2': patch
'@openid4vc/openid4vci': patch
'@openid4vc/openid4vp': patch
'@openid4vc/utils': patch
---

Move the `@openid4vc/*` packages from the `oid4vc-ts` repository into `identity-common-ts`. The `@openid4vc/*` packages keep being versioned together, separately from the other packages in this repository.

The packages stay ESM-only. Type declarations are now exposed through the `types` export condition, and `main` points to the ESM build. `require('@openid4vc/oauth2')` loads the ESM build, which needs a Node.js version that supports `require(esm)` (Node.js 20.19 and later, or 22.12 and later).

The builds no longer include copies of code from other `@openid4vc/*` packages. `@openid4vc/oauth2` bundled its own copy of `ValidationError`, so `instanceof ValidationError` checks against the class exported by `@openid4vc/utils` failed for some errors thrown by `@openid4vc/oauth2`. `@openid4vc/openid4vci` and `@openid4vc/openid4vp` bundled copies of `zOauth2ErrorResponse` and `addSecondsToDate`. `@openid4vc/oauth2` now exports the `VerifyClientAttestationOptions` type.
