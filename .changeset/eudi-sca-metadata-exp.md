---
'@owf/eudi-sca': patch
---

`fetchCredentialMetadata` rejects expired credential metadata. The `exp` check compared seconds as milliseconds, so it never failed, and whoever serves the metadata could replay an old version of it, including the transaction data types and labels shown for SCA confirmation.
