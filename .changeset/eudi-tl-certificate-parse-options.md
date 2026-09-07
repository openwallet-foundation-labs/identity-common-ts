---
'@owf/eudi-tl': minor
---

Expose ASN.1 parse options for the X.509 certificates embedded in a trusted list: `parseTrustedList`, `loadTrustedList` and `loadEuLotl` now accept `certificateParseOptions`, forwarding `asn1js.fromBER` resource limits (`maxDepth`, `maxNodes`, `maxContentLength`) so callers can bound the work done on untrusted input. Certificate parsing moved from `@peculiar/x509` to `@peculiar/asn1-x509`, which needs no global `Reflect` polyfill; the derived `subjectKeyIdentifier` values are unchanged
