---
'@owf/token-status-list': patch
---

Fix `aggregation_uri` being treated as required in the status list CBOR structure. `typedMap` only omits a key when its schema is *exact* optional, and `z.string().optional()` accepts `undefined`, so any status list CWT without an `aggregation_uri` failed to decode with `Expected key 'aggregation_uri' to be defined.` The encode side now omits the key instead of writing `undefined` for it.
