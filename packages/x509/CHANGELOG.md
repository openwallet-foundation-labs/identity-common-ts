# @owf/x509

## 0.5.0

### Minor Changes

- 6bcea3c: Add `@owf/x509` for environment agnostic X.509 certificate and CRL parsing, creation, signature verification and revocation checking, and `@owf/eudi-access-certificate` on top of it to parse, validate and create EUDI wallet-relying party access certificates per ETSI TS 119 411-8. Signing and signature verification are callbacks, so private keys are never passed to the libraries.

### Patch Changes

- @owf/identity-common@0.5.0
