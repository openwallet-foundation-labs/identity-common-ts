---
"dcql": patch
---

Merge claim outputs using own properties only. A credential with an object or array claim named after an `Object.prototype` member, such as `constructor` or `toString`, no longer fails the query.
