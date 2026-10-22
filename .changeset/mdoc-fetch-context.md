---
"@owf/mdoc": patch
---

`MdocContext.fetch` receives a third argument naming what it is retrieving, `{ type: 'statusList' | 'identifierList' }`, so an implementation can cache or time out per resource. An implementation written with a rest parameter needs its parameters named:

```diff
-fetch: (...args) => fetch(...args),
+fetch: (input, init) => fetch(input, init),
```
