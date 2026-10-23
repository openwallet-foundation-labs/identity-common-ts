---
"@openid4vc/openid4vci": minor
---

Support Credential Request encryption for regular and deferred issuance: validate issuer `credential_request_encryption` metadata, encrypt client requests when required or requested, and expose issuer decoders for encrypted and plaintext requests. Clients now refuse to send `credential_response_encryption` in plaintext. Issuer decoding rejects plaintext requests with response-encryption parameters or when request encryption is required; HTTP handlers must decode before calling the unchanged request parsers. Compression (`zip`) is not yet supported.
