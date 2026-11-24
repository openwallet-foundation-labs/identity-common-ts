---
'@openid4vc/openid4vp': patch
---

The `error_description` of these errors no longer contains a value of the authorization request or response, as RFC 6749 Section 5.2 only allows printable ASCII without `"` and `\` in it:

- the `request_uri` and client metadata URI, when fetching them fails
- the `typ` header of a request object with another `typ`
- the `client_id`, `client_id_scheme` and certificate SAN names, when the client identifier is not supported or does not match
- the `expected_origins` of a DC API request
- the transaction data hash `alg` of a presentation that the transaction data does not allow
