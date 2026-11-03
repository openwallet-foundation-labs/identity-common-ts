---
'@owf/cose': patch
---

`CoseError` and `CborError` extend `IdentityError` and are exported, so every COSE or CBOR error can be caught without listing the subclasses. Their `name`, `message` and `cause` are unchanged.
