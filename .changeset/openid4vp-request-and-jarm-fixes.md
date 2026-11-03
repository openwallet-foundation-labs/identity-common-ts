---
'@openid4vc/openid4vp': patch
---

- Encrypted JAR request objects verify again.
- `createOpenid4vpAuthorizationRequest` uses `now` for `iat` and `exp`.
- `jarm.expiresInSeconds` is the lifetime of a signed JARM response, 10 minutes by default, not its `exp`.
- A response is not encrypted to a `use: 'sig'` key unless its `kid` names it.
- `verifyJarmAuthorizationResponse` accepts a `jwk` or `x5c` header, whose trust the `verifyJws` callback decides, checks `exp`, `nbf` and `iat`, and keeps the `@owf/jose` error as `cause`.
