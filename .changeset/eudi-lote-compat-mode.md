---
'@owf/eudi-lote': minor
---

Add a `mode` and `allowedTerritories` option to `validateLoTEProfile`, and a `mode` option to `validateLoTE`, to validate lists in use that deviate from ETSI TS 119 602, such as the German EUDI Wallet lists.

- `mode: 'strict'` (default) validates as before. `mode: 'compat'` also accepts a `LoTELegalNotice` that is an array of localized URIs, `PolicyOrLegalNotice` items with both keys, and on a PID Providers List a `ServiceStatus` of `http://uri.etsi.org/19602/PidProvidersList/SvcStatus/notified` with a `StatusStartingTime`.
- `allowedTerritories` sets the accepted `SchemeTerritory` values in compat mode, `['EU']` by default. Strict mode requires `EU` (TS 119 602 D to I) and throws a `LoTEError` when `allowedTerritories` is passed.

```ts
validateLoTEProfile(lote, LoTEProfile.EUPIDProvidersList, { mode: 'compat', allowedTerritories: ['DE'] })
```
