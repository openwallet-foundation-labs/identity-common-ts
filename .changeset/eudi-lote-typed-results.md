---
'@owf/eudi-lote': minor
---

`validateLote` and `validateLoteProfile` return the validated document as `lote` when it is valid. `validateLote` types it as a `LoteDocument`, or in compat mode as the new `CompatLoteDocument`. `validateLoteProfile` also returns the LoTEType of the matched profile as `loteType`, which narrows `lote` to the new `LoteProfileDocument` of that profile, with the `LoTEType`, `ServiceTypeIdentifier` and `ServiceStatus` values the profile allows. `LOTE_TYPES` is exported to compare `loteType` with. `assertValidLote` takes a `mode` option too.

```ts
const result = validateLoteProfile(lote, [LoteProfile.EuPidProvidersList, LoteProfile.EuPubEaaProvidersList])
if (result.valid && result.loteType === LOTE_TYPES.EuPubEaaProvidersList) {
  // 'http://uri.etsi.org/19602/PubEAAProvidersList/SvcStatus/notified' | '.../withdrawn'
  result.lote.LoTE.TrustedEntitiesList?.[0]?.TrustedEntityServices[0]?.ServiceInformation.ServiceStatus
}
```

**Breaking:** `ValidationResult` is now a union on `valid`. A value you build yourself needs `lote` when `valid` is `true`. A profile now reports a wrong `LoTEType`, `LoTEVersionIdentifier`, `StatusDeterminationApproach`, `ServiceTypeIdentifier` or `ServiceStatus` before its other rules, which it checks once these pass.
