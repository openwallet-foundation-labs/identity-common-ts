---
'@owf/eudi-lote': minor
---

`validateLoteProfile` in compat mode accepts the lists of the French EUDI Wallet sandbox. It accepts a trusted entity without the `http://uri.etsi.org/19602/ListOfTrustedEntities/<type>/CC` URI (TS 119 602 D to H), and a Pub-EAA Providers List without `HistoricalInformationPeriod` (TS 119 602 H). Strict mode still requires both.

On a Pub-EAA Providers List, `validateLoteProfile` looks for the `http://uri.etsi.org/19602/ListOfTrustedEntities/PubEAAProvider/CC` URI in `TEAddress.TEElectronicAddress`, where TS 119 602 H.2 puts it. Compat mode also accepts it in `TEInformationURI`.

**Breaking:** strict mode rejects a Pub-EAA Providers List with the URI only in `TEInformationURI`, such as the EC acceptance list. Validate such a list with `mode: 'compat'`.
