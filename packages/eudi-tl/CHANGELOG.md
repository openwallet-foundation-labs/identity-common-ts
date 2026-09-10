# @owf/eudi-tl

## 0.4.0

### Minor Changes

- fb11a48: Expose ASN.1 parse options for the X.509 certificates embedded in a trusted list: `parseTrustedList`, `loadTrustedList` and `loadEuLotl` now accept `certificateParseOptions`, forwarding `asn1js.fromBER` resource limits (`maxDepth`, `maxNodes`, `maxContentLength`) so callers can bound the work done on untrusted input. Certificate parsing moved from `@peculiar/x509` to `@peculiar/asn1-x509`, which needs no global `Reflect` polyfill; the derived `subjectKeyIdentifier` values are unchanged
- 59b304c: New package: parse and verify ETSI TS 119 612 XML Trusted Lists (companion to @owf/eudi-lote for TS 119 602 JSON), exposing normalized trust anchors, caller-supplied profile validation, and XAdES signature verification with pinned scheme operator certificates and a caller-installable crypto engine (`setTrustedListCrypto`)
- 59b304c: Follow the EU trust hierarchy: trusted list pointers now expose the certificates the pointed-to list is signed with (`getPointerSigningCertificates`), and the EU LOTL signing certificates ship as pinned default anchors (`EU_LOTL_SIGNING_CERTIFICATES`, `getEuLotlTrustAnchors`, `verifyEuLotlSignature`, `loadEuLotl`) with provenance and a refresh script

### Patch Changes

- Updated dependencies [b7e7f15]
- Updated dependencies [5934a14]
  - @owf/identity-common@0.4.0
