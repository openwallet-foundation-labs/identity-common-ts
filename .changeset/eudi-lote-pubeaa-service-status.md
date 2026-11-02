---
'@owf/eudi-lote': minor
---

The `EUPubEAAProvidersList` profile rejected every list that follows ETSI TS 119 602 Annex H, as it forbade `ServiceStatus` and `StatusStartingTime`. It now requires a `ServiceStatus` on each service, either `http://uri.etsi.org/19602/PubEAAProvidersList/SvcStatus/notified` or `.../withdrawn`, and accepts a `StatusStartingTime`.

BREAKING: A valid Pub-EAA Providers List can now list withdrawn services. Only trust notified ones: the valid result of `validateLoTEProfile` has the trusted entities with only their notified services as `notifiedTrustedEntities`, and `getNotifiedTrustedEntities(lote)` returns the same.
