---
"@openid4vc/oauth2": patch
---

Match the `Authorization` header authentication scheme case-insensitively in `verifyResourceRequest`, as required by RFC 9110 §11.1. A request using e.g. `dpOp` or `bearer` is now accepted, and the scheme is resolved to its canonical form (`DPoP` / `Bearer`) for the rest of the verification.
