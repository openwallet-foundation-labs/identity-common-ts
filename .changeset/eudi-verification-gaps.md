---
'@owf/eudi-jades': patch
'@owf/eudi-attestation-schema': patch
'@owf/eudi-lote': patch
---

- `decodeJades` and `verifyJades` of `@owf/eudi-jades` reject a `detachedPayload` for the ObjectIdByURIHash mechanism. That signature covers the `hashV` digests in `sigD`, not the objects (ETSI TS 119 182-1 clause 5.2.8.3), so the call resolved although the payload passed in was never verified. Compare the digest of each object of `sigD.pars` with `sigD.hashV` instead.
- `verifySchemaMeta` of `@owf/eudi-attestation-schema` rejects a JWT whose `typ` is not `attestation-schema+jwt`, as `signSchemaMeta` sets it, so that another JWT signed with the same key is not taken for a SchemaMeta.
- The README of `@owf/eudi-lote` says that a LoTE must be verified before its trusted entities are used, as the validators only check its content.
