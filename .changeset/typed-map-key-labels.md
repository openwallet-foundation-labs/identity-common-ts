---
'@owf/cose': patch
---

Add a `keyLabels` option to `typedMap`, so validation errors can name a numeric CBOR label instead of only showing the number: `Expected key 'ExpirationTime (4)' to be defined.` A numeric TypeScript enum can be passed directly, and several can be merged with a spread.
