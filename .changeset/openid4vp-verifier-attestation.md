---
'@openid4vc/openid4vp': minor
---

**Breaking:** a `verifier_attestation` request is verified as OpenID4VP 1.0 Sections 5.9.3 and 12 require. The attestation in the `jwt` header must verify, its `sub` must be the client identifier, the `redirect_uri` must be one of its `redirect_uris` when it has them, and the request object must be signed with its `cnf` key. The `verifyJws` callback decides whether the issuer is trusted. Recognize the attestation with `isJwtTyp(typ, 'verifier-attestation+jwt')`. New: `verifyVerifierAttestation`, and `verifierAttestation` on the verified JAR request.
