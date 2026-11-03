---
'@openid4vc/utils': minor
'@openid4vc/openid4vp': patch
'@owf/token-status-list': minor
'@owf/mdoc': minor
'@sd-jwt/core': patch
'@owf/eudi-registration-certificate': patch
---

Media types are compared with `isMediaType` and JOSE `typ` values with `isJwtTyp`, both from `@owf/identity-common`. JARM accepts its `Content-Type` in any casing. A Key Binding JWT and a registration certificate accept their `typ` in any casing and with the `application/` prefix (RFC 7515 Section 4.1.9).

**Breaking:** `isContentType` and `isResponseContentType` are removed from `@openid4vc/utils`. Replace `isContentType(contentType, value)` with `isMediaType(value, contentType)` and `isResponseContentType(contentType, response)` with `isMediaType(response.headers.get('Content-Type'), contentType)`. `MediaTypes` is renamed to `StatusListMediaTypes` in `@owf/token-status-list` and to `MdocMediaTypes` in `@owf/mdoc`.
