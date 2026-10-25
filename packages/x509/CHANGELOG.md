# @owf/x509

## 0.6.0

### Patch Changes

- @owf/identity-common@0.6.0

## 0.5.0

### Minor Changes

- b4105be: Drop the CommonJS build from all packages; only ESM is now published. All environments targeted by this library support ESM natively. This removes the dual-package hazard that caused `instanceof` checks to fail in Metro/Hermes and similar single-module-system runtimes.
- 6bcea3c: Add `@owf/x509` for environment agnostic X.509 certificate and CRL parsing, creation, signature verification and revocation checking, and `@owf/eudi-access-certificate` on top of it to parse, validate and create EUDI wallet-relying party access certificates per ETSI TS 119 411-8. Signing and signature verification are callbacks, so private keys are never passed to the libraries.

### Patch Changes

- Updated dependencies [b4105be]
  - @owf/identity-common@0.5.0
