---
'@owf/token-status-list': minor
---

Share the Status List Token claim checks between the CWT and JWT serializations, and add clock skew.

`verifyStatusListClaims` is now the single implementation of the claim requirements from the Token Status List specification:

- `sub` present and equal to the URI the token was referenced by
- `iat` present and not in the future
- `exp` not in the past

Both accept `skewSeconds` (default 30) as the clock tolerance for `exp` and `iat`, and `requireExpirationTime` for profiles that make `exp` mandatory (e.g. ISO/IEC 18013-5 second edition)

Fixes: the JWT `verifyStatus` read the subject from a `subject` claim, which a conformant Status List Token never carries (the registered claim is `sub`)
