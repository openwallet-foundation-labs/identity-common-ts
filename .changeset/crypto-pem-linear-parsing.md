---
"@owf/crypto": patch
---

`parseCertificateChain`, `parseCertificate` and `pemToDer` find the PEM boundaries of RFC 7468 Section 2 in linear time. Input with many `-----BEGIN` lines and no `-----END` line took quadratic time before. The accepted input does not change.
