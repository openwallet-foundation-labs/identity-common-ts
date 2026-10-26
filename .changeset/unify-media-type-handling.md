---
'@owf/identity-common': minor
'@openid4vc/utils': major
'@openid4vc/openid4vp': patch
'@owf/token-status-list': major
'@owf/mdoc': major
---

Centralize media-type and JOSE `typ` comparison in `@owf/identity-common`. OpenID4VC Utils now uses exact media-type comparison instead of substring matching, so lookalike values such as `application/json-seq` and parameter-only matches such as `multipart/related; type="application/json"` are rejected. Case-insensitive matches and valid media-type parameters remain supported. The `isContentType` and `isResponseContentType` utility exports are removed in favor of `isMediaType` from `@owf/identity-common`. JARM content-type checks are now case-insensitive, and Status List and Mdoc media-type registries use the qualified names `StatusListMediaTypes` and `MdocMediaTypes` without legacy aliases.
