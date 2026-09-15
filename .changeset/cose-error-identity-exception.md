---
'@owf/cose': patch
---

`CoseError` and `CborError` now extend `IdentityException`, so every error raised by the identity-common packages can be caught in one place. `CoseError` is also exported now, which makes it possible to catch every COSE error without listing the individual classes.

The `name`, `message` and `cause` of both are unchanged, and `instanceof` keeps holding for each subclass.
