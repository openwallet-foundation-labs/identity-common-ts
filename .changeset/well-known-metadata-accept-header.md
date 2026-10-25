---
'@openid4vc/utils': patch
'@openid4vc/oauth2': patch
---

Requests made with `createZodFetcher` now send the expected content types as the `Accept` header, unless the request already sets one. The first content type is preferred, and later ones get decreasing `q` values. Before, the expected content types were only checked against the response `Content-Type`.
