---
'@owf/cose': minor
---

Verify a CWT from the CWT itself.

`CwtPayload.verifyClaims` checks the claims set: that the claims the CWT type requires are present, that `iss` / `sub` / `aud` are the expected ones, and that the token is within its validity window (compared against `now` with a `skewSeconds` of 30 seconds by default). Nothing is required unless `requiredClaims` says so (or an extended `CwtPayload` class defines it as required).

A CWT type overrides/extends `verifyClaims` to apply its own rules, and the options it takes travel with it: `Cwt.verifyClaims` and `Cwt.verify` forward the payload class's own option type, so a CWT type that requires more than the registered claims requires it on the `Cwt` methods too.

`Cwt.verify` verifies a token completely (signature/tag and claims + subclass verifications):

```ts
await cwt.verify({ key, expectedSubject: 'https://example.com/statuslists/1' }, { sign1: sign1Context })
```

The verify method supports both `Sign1` and `Mac0` verification, so the `ctx` takes a callback for each (both optional) To make that distinction available, `Cwt` now holds `signature` and `tag` separately instead of one merged `signatureOrTag` field. `signatureOrTag` remains as a read-only getter over the two, and a CWT constructed with both is rejected.
