---
'@owf/eudi-attestation-schema': minor
---

Resolve `dc+sd-jwt` references as SD-JWT VC Type Metadata rather than as bare JSON Schema.

`resolveSchemaReferences` now validates the resolved document against the new `TypeMetadataSchema`, cross-checks its `vct` against `meta.vct` from the catalogue entry, follows and merges the `extends` chain (verifying `extends#integrity` on each hop, with cycle detection and a `maxExtendsDepth` bound defaulting to 10), and resolves `schema_uri` as a second hop with `schema_uri#integrity` verified. The merged document is exposed as `ResolvedSchemaReference.typeMetadata`, and `parsedSchema` now holds the JSON Schema itself. References that are a plain JSON Schema remain supported.

DCQL claims are taken verbatim from Type Metadata `claims[].path` when present, since Type Metadata already states every claim as a claims path pointer, and are inferred from the JSON Schema only as a fallback. The same claim set feeds `buildCredentialConfigurationTemplate`.

Add an optional `issuanceProfile` to `SchemaMeta` describing the policy constraints a conformant issuer must satisfy, together with `buildCredentialConfigurationTemplate` and `validateIssuerMetadataAgainstProfile` for deriving and checking an OID4VCI `credential_configurations_supported` entry.

**Breaking:** `verifyIntegrity` now defaults to `true`, and integrity is verified over the bytes as transferred. A `resolve` implementation must return the response body as a `string` or `Uint8Array`; returning already-parsed content throws unless `verifyIntegrity` is `false`. Previously the digest was computed over `JSON.stringify(content)` for parsed content, which does not match the transferred bytes.

`version` is now validated as SemVer, the `x509Certificate` base64 pattern rejects lengths that are not a multiple of four, and the `integrity` pattern states that only `sha256` is supported.
