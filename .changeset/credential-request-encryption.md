---
"@openid4vc/openid4vci": minor
---

Support Credential Request encryption for regular and deferred issuance:

- Validate issuer `credential_request_encryption` metadata and encrypt client requests when required or when callers provide `credentialRequestEncryption`, with optional `kid` and `enc` selectors.
- Add async issuer methods `parseCredentialRequestFromBody` and `parseDeferredCredentialRequestFromBody`, accepting `{ body, contentType, issuerMetadata }`. These methods decode JSON text or parsed objects and validate and decrypt compact JWE requests using the issuer's `decryptJwe` callback.
- Retain the existing synchronous parsed-object methods with unchanged signatures, but deprecate them in favor of the body-parsing methods.
- Require encrypted requests when issuer metadata mandates encryption, or when response-encryption parameters are included for V1 or an issuer advertising request encryption. Preserve plaintext requests with encrypted responses for earlier drafts when request encryption is not advertised.
- Align `verifyCredentialRequestEncryption` with the existing response verifier's positional arguments.
- Reject unsupported compression (`zip`) in credential requests and response-encryption parameters.
