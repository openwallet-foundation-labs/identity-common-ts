---
'@owf/eudi-tl': minor
---

Follow the EU trust hierarchy: trusted list pointers now expose the certificates the pointed-to list is signed with (`getPointerSigningCertificates`), and the EU LOTL signing certificates ship as pinned default anchors (`EU_LOTL_SIGNING_CERTIFICATES`, `getEuLotlTrustAnchors`, `verifyEuLotlSignature`, `loadEuLotl`) with provenance and a refresh script
