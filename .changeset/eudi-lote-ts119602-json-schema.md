---
'@owf/eudi-lote': minor
---

Accept lists that are valid under the ETSI TS 119 602 v1.1.1 JSON schema: `TrustedEntitiesList`, `ServiceSupplyPoints[].ServiceType` and the `Locality` and `PostalCode` of a postal address are now optional, and `LoTELegalNotice` may be a plain string as well as a localized string. `LoTE.TrustedEntitiesList` is now typed as optional.
