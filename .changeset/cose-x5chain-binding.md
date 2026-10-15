---
"@owf/cose": patch
---

Add `getIntegrityProtectedX5Chain`, which reads the `x5chain` of a COSE structure from the protected header, or else from the unprotected header when a protected `x5t` (SHA-256) matches its leaf, as RFC 9360 requires. An unbound unprotected `x5chain` throws `CoseX5ChainNotBoundError`.
