---
'@openid4vc/utils': major
'@openid4vc/openid4vp': patch
'@owf/token-status-list': major
'@owf/mdoc': major
'@sd-jwt/core': patch
'@owf/eudi-registration-certificate': patch
---

Media types are compared with `isMediaType` and JOSE `typ` values with `isJwtTyp`, both from `@owf/identity-common`. The `isContentType` and `isResponseContentType` exports of `@openid4vc/utils` are removed: use `isMediaType` instead. JARM accepts its `Content-Type` in any casing. The Status List and Mdoc media-type registries are renamed to `StatusListMediaTypes` and `MdocMediaTypes`, without aliases for `MediaTypes`. A Key Binding JWT and a registration certificate accept their `typ` in any casing and with the `application/` prefix (RFC 7515 Section 4.1.9).
