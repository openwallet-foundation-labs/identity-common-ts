# @owf/x509

## 0.8.0

### Minor Changes

- 04cfd04: Error classes are named `FooError` and zod schemas `zFoo` in all packages.
  
  **Breaking:** `*Exception` is renamed to `*Error`, e.g. `IdentityException` to `IdentityError`, `SDJWTException` to `SdJwtError`, `JwtTimeClaimException` to `JwtTimeClaimError`, `X509Exception` to `X509Error` and `SLException` to `StatusListError`. The `name` of the errors changes with it. Zod schemas are renamed from `FooSchema` (or `fooSchema`) to `zFoo`, e.g. `TypeMetadataFormatSchema` to `zTypeMetadataFormat`, `SchemaMetaSchema` to `zSchemaMeta`, `issuerSignedItemSchema` to `zIssuerSignedItem` and `Iso4217CurrencyCode` to `zIso4217CurrencyCode`.

### Patch Changes

- Updated dependencies [0f663bf]
- Updated dependencies [ebd0b4b]
- Updated dependencies [21cd668]
- Updated dependencies [ec2ed51]
- Updated dependencies [ec2ed51]
- Updated dependencies [cb487f1]
- Updated dependencies [5fff735]
- Updated dependencies [04cfd04]
  - @owf/identity-common@0.8.0

## 0.7.0

### Patch Changes

- Updated dependencies [23f227b]
  - @owf/identity-common@0.7.0

## 0.6.2

### Patch Changes

- @owf/identity-common@0.6.2

## 0.6.1

### Patch Changes

- Updated dependencies [bf9b7c8]
  - @owf/identity-common@0.6.1

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
