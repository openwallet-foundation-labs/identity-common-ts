---
'@sd-jwt/sd-jwt-vc': patch
---

Fix the mandatory claim checks of `verifyTypeMetadata`: claim names such as `constructor` are no longer found on `Object.prototype`, a mandatory claim under a `null` path is undisclosed when every element is withheld and missing when the value is not an array, and the vct of type metadata passed by the caller is compared before its `extends` chain is resolved.
