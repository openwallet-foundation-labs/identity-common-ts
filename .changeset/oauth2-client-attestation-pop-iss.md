---
'@openid4vc/oauth2': patch
---

The error of `verifyClientAttestationPopJwt`, and so of `verifyClientAttestation`, for a PoP JWT whose `iss` doesn't match the `sub` of the client attestation escapes the control characters of the `iss` and cuts it off after 200 characters, with `errorMessageValue` of `@owf/identity-common`. The client chooses the `iss`, and it is checked before the signature of the PoP, so it can no longer start a line of its own in a log.
