---
"@openid4vc/openid4vci": patch
---

Pass the `credential_response_encryption` JWK to the `decryptJwe` callback when decrypting credential and deferred credential responses, matching how the issuer binds the key when decrypting credential requests.
