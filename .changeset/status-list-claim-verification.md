---
'@owf/token-status-list': minor
---

Verify the claims of a Status List Token, and add clock skew.

`StatusListCwt(Payload).verifyClaims` verify the Token Status List requirements on top of the generic CWT claim verification: `sub` and `iat` are REQUIRED, and `sub` has to match the URI the token was referenced by. `StatusListCwt(Payload).verifyStatus(idx)` checks that the status at an index is valid.

`StatusListCwt.verify` verifies a status list token completely:

- signature or authentication tag
- claims
- the status of a specific index if `idx` is given.

```ts
await statusListCwt.verify({ key, uri, idx }, { sign1: sign1Context })
```

Breaking change: `StatusListCwt.verifyStatus` does not verify the claims anymore, this is handled by `verifyClaims` or the general `verify` method.

Both serializations accept `skewSeconds` (default 30) as the clock tolerance for `exp`, `nbf` and `iat`. The CWT one takes `requiredClaims` for profiles that make a further claim mandatory (e.g. `exp` for ISO/IEC 18013-5 second edition), the JWT one `requireExpirationTime`. A `nbf` in the future is now rejected.

Fixes: the JWT `verifyStatus` read the subject from a `subject` claim, which a conformant Status List Token never carries (the registered claim is `sub`)
