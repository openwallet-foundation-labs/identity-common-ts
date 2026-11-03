---
'@openid4vc/openid4vci': patch
'@openid4vc/openid4vp': patch
---

`resolveCredentialOffer` keeps the offer, which can carry the pre-authorized code, out of its error messages. Transaction data that is not base64url encoded UTF-8 or does not validate gives `invalid_transaction_data`.
