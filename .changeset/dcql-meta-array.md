---
'dcql': patch
---

`DcqlQuery.parse` rejects a `meta` that is an array for `mso_mdoc`, `dc+sd-jwt` and `vc+sd-jwt` credential queries. It accepted one as an object without members, as valibot's object schema accepts arrays.
