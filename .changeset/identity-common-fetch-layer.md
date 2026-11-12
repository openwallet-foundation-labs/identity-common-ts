---
'@owf/identity-common': minor
---

Add `fetchWithLimits` and `fetchAndParse`, through which the packages of this repository fetch. They read the body of a response within a maximum size, and return a `Response` that holds the body in memory. `fetchAndParse` also parses the body of a 2xx response of an accepted media type, e.g. with a zod schema or into a class instance.

A package takes a `fetch` (`FetchCallback`) and `fetchLimits` (`FetchLimits`). The fetch callback gets what is fetched as its third argument, `{ type }` of `FetchType`, e.g. `statusList` or `jwks`, so it can apply its own policy per type and does not have to limit the size of the response. The global `fetch` still fits. `FetchLimits` sets `maxResponseBytes` for every type and `maxResponseBytesByType` per type. By default a response is at most 16 MiB for `statusList` and `identifierList`, 1 MiB for `typeMetadata` and 10 MiB for every other type.
