---
"@openid4vc/openid4vci": minor
---

Support Credential Request encryption for regular and deferred issuance:

- Reject plaintext requests before payload validation when issuer metadata requires request encryption.
- Validate issuer `credential_request_encryption` metadata and encrypt client requests when required or when callers provide `credentialRequestEncryption`, with optional `kid` and `enc` selectors.
- **Breaking:** Both `Openid4vciIssuer.parseCredentialRequest` and `Openid4vciIssuer.parseDeferredCredentialRequest` now return Promises and must be awaited. Their options require `contentType` and use `body` in place of `credentialRequest` and `deferredCredentialRequest`, respectively, alongside `issuerMetadata`. Pass a parsed JSON object for `application/json` or a compact JWE string for `application/jwt`; encrypted requests are decrypted using the issuer's `decryptJwe` callback.
- Do not send plaintext requests containing `credential_response_encryption` to OpenID4VCI V1 issuers, per §8.2. Encrypt these requests, or fail locally if the issuer does not advertise request encryption. Also require encrypted requests when issuer metadata mandates encryption or when response-encryption parameters are included for an issuer advertising request encryption. Preserve plaintext requests with encrypted responses for earlier drafts when request encryption is not advertised.
- Align `verifyCredentialRequestEncryption` with the existing response verifier's positional arguments.
- Reject unsupported compression (`zip`) in credential requests and response-encryption parameters.
- Document that decryption callbacks return `{ decrypted: false }` for invalid ciphertext and throw only for internal failures, which are reported as server errors.
- Report a server error when a plaintext request requests response encryption from a V1 issuer advertising response encryption without request-encryption support.
