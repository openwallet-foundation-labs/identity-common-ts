---
'@openid4vc/openid4vci': patch
---

Add a `signedMetadata` option to `Openid4vciClient.resolveIssuerMetadata` to choose whether the credential issuer metadata must be signed: `required`, `preferred` or `disallowed`. The default is `preferred` with a `verifyJwt` callback, and `disallowed` without one. Accepting signed metadata requires the `verifyJwt` callback, which is now part of the `Openid4vciClient` callbacks type.

The option is now sent as the `Accept` header. With `preferred` this is `application/jwt, application/json;q=0.9`, so issuers that only return signed metadata when the client asks for a JWT now return it.
