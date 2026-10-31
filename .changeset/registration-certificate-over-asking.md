---
'@owf/eudi-registration-certificate': minor
---

Add `checkOverAsking(dcqlQuery, credentials)`, which compares the DCQL query of an OpenID4VP request with the `credentials` of a WRPRC and reports every credential and claim the request asks for beyond the registration, as findings with codes from `OVER_ASKING_CODES` and paths into the query. A requested credential needs a registered one of the same format whose `meta` it stays within, and a requested claim a registered claim with the same or a parent path, and with only registered `values` when the registered claim lists them. A credential query without claims only has its credential checked, and a registered credential without claims gives a warning.
