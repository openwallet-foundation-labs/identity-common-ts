---
'@owf/identity-common': minor
---

Add `fetchWithLimits` and `fetchAndParse`, through which the packages of this repository fetch. They read the body of a response within a maximum size, and return a `Response` that holds the body in memory. `fetchAndParse` also parses the body of a 2xx response, e.g. with a zod schema or into a class instance, and rejects a 2xx response of a media type it does not accept.

A package takes a `fetch` (`FetchCallback`) and `fetchLimits` (`FetchLimits`), both generic in the types the package fetches. The fetch callback gets what is fetched as its third argument, `{ type }`, e.g. `statusList` or `jwks`, so it can apply its own policy per type and does not have to limit the size of the response. The global `fetch` still fits. `FetchLimits` sets `maxResponseBytes` for every type and `maxResponseBytesByType` per type. Without either, a package sets the default for the type, such as 16 MiB for a status list, and otherwise a response is at most 10 MiB.
