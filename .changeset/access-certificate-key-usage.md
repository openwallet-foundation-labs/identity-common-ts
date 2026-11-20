---
'@owf/eudi-access-certificate': minor
---

`validateAccessCertificate` checks the key usage against ETSI EN 319 412-2 NAT-4.3.2-1 (EN 319 412-3 LEG-4.3.1-2 for legal persons): the extension must be present and be one of the settings of table 1 that can sign. An access certificate with only `nonRepudiation` (type A) is now accepted without a warning. A missing key usage is an error (`missing_key_usage`), and so is one without `digitalSignature` or `nonRepudiation`, or with `nonRepudiation` and `keyEncipherment` or `keyAgreement` but without `digitalSignature` (`invalid_key_usage`).

**Breaking:** the `missing_digital_signature_key_usage` warning is removed. Check for `missing_key_usage` and `invalid_key_usage` instead.
