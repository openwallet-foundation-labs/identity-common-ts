---
'@owf/eudi-lote': minor
---

`validateLoTE` and `validateLoTEProfile` return the validated document as `lote` when it is valid. `validateLoTE` types it as a `LoTEDocument`, or in compat mode as the new `CompatLoTEDocument`. `validateLoTEProfile` also returns the LoTEType of the matched profile as `loteType`, which narrows `lote` to the new `LoTEProfileDocument` of that profile, with the `LoTEType`, `ServiceTypeIdentifier` and `ServiceStatus` values the profile allows. `LOTE_TYPES` is exported to compare `loteType` with. `assertValidLoTE` takes a `mode` option too.

```ts
const result = validateLoTEProfile(lote, [LoTEProfile.EUPIDProvidersList, LoTEProfile.EUPubEAAProvidersList])
if (result.valid && result.loteType === LOTE_TYPES.EUPubEAAProvidersList) {
  // 'http://uri.etsi.org/19602/PubEAAProvidersList/SvcStatus/notified' | '.../withdrawn'
  result.lote.LoTE.TrustedEntitiesList?.[0]?.TrustedEntityServices[0]?.ServiceInformation.ServiceStatus
}
```

**Breaking:** `ValidationResult` is now a union on `valid`. A value you build yourself needs `lote` when `valid` is `true`. A profile now reports a wrong `LoTEType`, `LoTEVersionIdentifier`, `StatusDeterminationApproach`, `ServiceTypeIdentifier` or `ServiceStatus` before its other rules, which it checks once these pass.
