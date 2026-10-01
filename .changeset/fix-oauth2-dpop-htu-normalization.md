---
"@openid4vc/oauth2": patch
"@openid4vc/utils": patch
---

Normalize the `htu` claim of a DPoP proof the same way as the request URL before comparing them, so query and fragment are ignored (RFC 9449 §4.3) and an uppercase host or explicit default port no longer cause a mismatch (RFC 3986 §6.2.2, §6.2.3). `zHttpsUrl` now accepts the URL scheme case-insensitively (RFC 3986 §3.1).
