---
"@openid4vc/oauth2": patch
---

Report a client attestation or client attestation PoP JWT that fails schema validation (e.g. a missing `sub`, `exp`, `cnf.jwk` or `jti` claim) as `invalid_client` with status `401`, consistent with signature and expiry failures. Previously the `ValidationError` was reported as a `500` `server_error` by `verifyClientAttestation`, and was not mapped to an OAuth2 error at all for the `attest_jwt_client_auth_dpop` method.
