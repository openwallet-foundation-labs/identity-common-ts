---
'@openid4vc/openid4vci': patch
---

`verifyCredentialRequestJwtProof` verifies the `key_attestation` in the proof header, and `verifyInteractiveAuthorizationInitialRequest` the JAR request object, at the `now` that is passed in rather than at the current time. This also applies to these methods of `Openid4vciIssuer`.
