---
'@openid4vc/utils': patch
'@openid4vc/oauth2': patch
---

Security fix: `encodeWwwAuthenticateHeader`, and so `Oauth2ResourceUnauthorizedError.toHeaderValue()`, always returns a valid header value. Control and non-ASCII characters are replaced with a space and an `error_description` longer than 500 characters is truncated, so a value taken from the request can no longer inject a header or make setting the header throw.

`parseWwwAuthenticateHeader`, and so `Oauth2ResourceUnauthorizedError.fromHeaderValue()`, unescapes every escaped character in a quoted string (`\\` becomes `\`), not only an escaped quote.
