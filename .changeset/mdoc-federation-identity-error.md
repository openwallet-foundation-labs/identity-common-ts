---
'@owf/mdoc': patch
'@owf/openid-federation': patch
---

`MdlError` of `@owf/mdoc`, and `OpenidFederationError`, `PolicyValidationError` and `PolicyOperatorMergeError` of `@owf/openid-federation`, extend `IdentityError` instead of `Error`. The `name` of an `MdlError` is now its class, where it was `Error`.
