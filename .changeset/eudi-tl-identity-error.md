---
'@owf/eudi-tl': patch
---

`TrustedListError` extends `IdentityError` from `@owf/identity-common` instead of `Error`, so `instanceof IdentityError` catches it too.
