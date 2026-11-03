---
'@openid4vc/utils': minor
'@openid4vc/oauth2': minor
'@openid4vc/openid4vci': minor
'@openid4vc/openid4vp': minor
---

Schema issues have the codes of `@owf/identity-common`, such as `missing_value` or `invalid_format`, instead of `invalid_value`.

**Breaking:** values the specifications don't allow to be empty are rejected when empty, e.g. `client_id`, `nonce`, `c_nonce`, `pre-authorized_code`, `vct`, `access_token` and `jti`. `dpop_signing_alg_values_supported` rejects `none` (RFC 9449 Section 4.2).
