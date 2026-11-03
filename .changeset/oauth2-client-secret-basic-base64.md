---
'@openid4vc/oauth2': patch
---

`clientAuthenticationClientSecretBasic` form-urlencodes the client id and secret and encodes them with base64 instead of base64url (RFC 6749 Section 2.3.1, RFC 7617).
