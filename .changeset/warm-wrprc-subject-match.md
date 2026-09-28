---
'@owf/eudi-wrprc': major
---

Require the access-certificate subject in WRPRC validation, signing, parsing, and decoding APIs. Validate it against `intermediary.sub` when present and `sub` otherwise.
