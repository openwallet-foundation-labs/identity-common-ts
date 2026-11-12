---
'@owf/mdoc': minor
---

The status list and identifier list of an mdoc are read within the new `fetchLimits` of `MdocContext` (see `FetchLimits` of `@owf/identity-common`), 16 MiB each by default. Before, an identifier list response of any size was read whole. `MdocContext.fetch` is a `FetchCallback` of `@owf/identity-common`, and `MdocFetchContext` its `FetchContext`, so an implementation of it does not change.
