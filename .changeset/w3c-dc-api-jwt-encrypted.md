---
"@openid4vc/openid4vp": patch
---

Treat the legacy `w3c_dc_api.jwt` response mode as an encrypted response mode, like `dc_api.jwt`. Before, a holder could send an unencrypted response to a verifier that requested `w3c_dc_api.jwt`.
