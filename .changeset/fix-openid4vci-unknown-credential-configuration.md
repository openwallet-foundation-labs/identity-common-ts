---
"@openid4vc/openid4vci": patch
---

Return the `unknown_credential_configuration` error (OpenID4VCI 1.0 §8.3.1) when a credential request references a `credential_configuration_id` that is not in the issuer's `credential_configurations_supported`. Previously `parseCredentialRequest` threw a generic `Oauth2Error` and `Openid4vciIssuer.parseCredentialRequest` reported it as `invalid_credential_request`.
