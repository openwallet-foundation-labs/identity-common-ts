---
'@owf/cose': minor
---

Supply `externalAad` at the call that uses it, rather than holding it on the structure. It is now a parameter of every sign and verify call that may use it. This fixes an issue where the property was not correctly used when provided.

```ts
const token = await cwt.signAndEncode({ signingKey, algorithm, externalAad }, sign1Context)
await Cwt.fromToken(token, { payload: CwtPayload }).verify({ key, externalAad }, { sign1: sign1Context })
```

Breaking: `externalAad` is removed from `Sign1Options`, `Mac0Options` and `CwtOptions`, and from the `Sign1.externalAad` / `Mac0.externalAad` / `Cwt.externalAad` properties. Pass it to the call instead.
