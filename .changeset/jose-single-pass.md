---
'@owf/jose': patch
---

`decodeJwt`, `parseJws` and `signJwt` validate the header and the claims set against the registered schema once when no schema is passed, instead of twice. `decodeJwt` reads the claims from the payload bytes `parseJws` already decoded, so a large token is base64url decoded once.
