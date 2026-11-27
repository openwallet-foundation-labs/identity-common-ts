---
'@openid4vc/oauth2': patch
'@openid4vc/openid4vci': patch
---

The `error_description` of these errors no longer contains a value of the request, as RFC 6749 Section 5.2 only allows printable ASCII without `"` and `\` in it:

- `parseJarRequest` and `verifyJarRequest`: the `request_uri` in the `invalid_request_uri` error when fetching it fails.
- `verifyJarRequest`: the `typ` header in the `invalid_request_object` error for a request object with another `typ`. The expected values are no longer in `"` either.
- `Openid4vciIssuer.parseCredentialRequest`: the `credential_configuration_id` in the `unknown_credential_configuration` error.
