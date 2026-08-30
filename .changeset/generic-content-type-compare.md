---
'@owf/identity-common': patch
'@owf/token-status-list': patch
---

Add `extractMediaType` and `isMediaType` to `@owf/identity-common` for comparing `Content-Type` header values against expected media types, ignoring casing and parameters.

`fetchStatusList` now uses `isMediaType` instead of an exact string match on the `Content-Type` response header, so a status list served as e.g. `application/statuslist+jwt; charset=utf-8` or `Application/StatusList+CWT` is no longer rejected.
