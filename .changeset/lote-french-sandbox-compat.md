---
'@owf/eudi-lote': minor
---

`validateLoteProfile` in compat mode accepts a Pub-EAA Providers List without `HistoricalInformationPeriod`, as the French EUDI Wallet sandbox publishes it. Strict mode still requires it with value `65535` (TS 119 602 H.1).

On a Pub-EAA Providers List, `validateLoteProfile` looks for the `http://uri.etsi.org/19602/ListOfTrustedEntities/PubEAAProvider/CC` URI in `TEAddress.TEElectronicAddress`, where TS 119 602 H.2 puts it. Compat mode also accepts it in `TEInformationURI`.

**Breaking:** strict mode rejects a Pub-EAA Providers List with the URI only in `TEInformationURI`, such as the EC acceptance list. Validate such a list with `mode: 'compat'`.
