---
'@openid4vc/oauth2': patch
---

`clientAuthenticationClientSecretBasic` form-urlencodes the client id and secret (RFC 6749 Section 2.3.1 and Appendix B) and encodes them with base64 with padding instead of base64url (RFC 7617 Section 2). Authorization servers such as Keycloak rejected the header unless the length of `clientId:clientSecret` was a multiple of three.

An authorization server that compares the secret without decoding it rejects a secret with characters other than letters, digits and `*-._`. Use `clientAuthenticationClientSecretPost` or a custom `clientAuthentication` callback for those.
