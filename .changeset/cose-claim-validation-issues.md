---
'@owf/cose': minor
---

**Breaking:** `CwtClaimVerificationError` is a `ValidationError` with an issue per failing claim, such as `expired`, and no longer a `CoseError`.
