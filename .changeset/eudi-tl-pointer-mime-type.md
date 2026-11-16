---
'@owf/eudi-tl': minor
---

`parseTrustedList`, `loadTrustedList` and `loadEuLotl` return the `MimeType` of each pointer to another list as `mimeType` of `TrustedListPointer` (ETSI TS 119 612 clause 5.3.13), and `getPointerSigningCertificates` filters by it, case-insensitively. The EU List of Trusted Lists points to a PDF of some national lists next to the XML, which a verifier can now skip.
