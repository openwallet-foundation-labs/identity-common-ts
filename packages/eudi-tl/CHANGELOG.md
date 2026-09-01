# @owf/eudi-tl

## 0.4.0

### Minor Changes

- 59b304c: New package: parse and verify ETSI TS 119 612 XML Trusted Lists (companion to @owf/eudi-lote for TS 119 602 JSON), exposing normalized trust anchors, caller-supplied profile validation, and XAdES signature verification with pinned scheme operator certificates and a caller-installable crypto engine (`setTrustedListCrypto`)
- 59b304c: Follow the EU trust hierarchy: trusted list pointers now expose the certificates the pointed-to list is signed with (`getPointerSigningCertificates`), and the EU LOTL signing certificates ship as pinned default anchors (`EU_LOTL_SIGNING_CERTIFICATES`, `getEuLotlTrustAnchors`, `verifyEuLotlSignature`, `loadEuLotl`) with provenance and a refresh script

### Patch Changes

- Updated dependencies [b7e7f15]
- Updated dependencies [5934a14]
  - @owf/identity-common@0.4.0
