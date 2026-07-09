# @owf/eudi-attestation-schema

> **⚠️ Experimental:** This package is experimental. The underlying ETSI specification is not yet finalized, and this implementation is used to test the upcoming approach. Breaking changes are possible until the specification is stable.

SDK for creating, signing, and validating attestation schema metadata (SchemaMeta) per the **EUDI TS11 Catalogue of Attestations** specification.

## Overview

This SDK implements the TS11 data model for the EUDI Catalogue of Attestations, enabling:

- **Create SchemaMeta objects** using a fluent builder API
- **Validate SchemaMeta documents** against the TS11 schema
- **Sign SchemaMeta as JWS** with private keys or custom signers (HSM/KMS)

## Specification Reference

- [TS11 — Interfaces and formats for catalogue of attributes and catalogue of attestations](https://github.com/eu-digital-identity-wallet/eudi-doc-standards-and-technical-specifications/blob/main/docs/technical-specifications/ts11-interfaces-and-formats-for-catalogue-of-attributes-and-catalogue-of-schemes.md)

## Installation

```bash
npm install @owf/eudi-attestation-schema
# or
pnpm add @owf/eudi-attestation-schema
```

## Usage

### Creating a SchemaMeta Object

```typescript
import {
  schemaMeta,
  schemaURI,
  trustAuthority,
} from '@owf/eudi-attestation-schema';

const meta = schemaMeta()
  .id('https://gym.example.com/attestations/gym-membership-card')
  .version('1.0.0')
  .rulebookURI('https://example.com/rulebooks/gym-membership/1.0.0.md')
  .rulebookIntegrity('sha256-cJe/IG7DijmXd2FpecyWJVnZ9EuKKprly5auxGm1uIw=')
  .addTrustAuthority(
    trustAuthority()
      .frameworkType('etsi_tl')
      .value('https://example.com/trust-lists/gym-members.jws')
      .isLoTE(true)
      .build()
  )
  .attestationLoS('iso_18045_basic')
  .bindingType('key')
  .addSchemaURI(
    schemaURI()
      .format('dc+sd-jwt')
      .uri('https://example.com/schemas/gym-membership.dc+sd-jwt.json')
      .meta({ vct: 'eu.example.gym-membership.1' })
      .integrity('sha256-M8H+reBt9Nr/s8CRicJrthAnk7UdWyTyONW0N8Z/Axw=')
      .build()
  )
  .build();
```

### Validating a SchemaMeta Document

```typescript
import {
  validateSchemaMeta,
  assertValidSchemaMeta,
} from '@owf/eudi-attestation-schema';

// Returns { valid: boolean, errors: ValidationError[] }
const result = validateSchemaMeta(untrustedData);
if (!result.valid) {
  console.error('Validation errors:', result.errors);
}

// Or use the assertion form (throws SchemaMetaException on invalid input)
assertValidSchemaMeta(untrustedData);
// untrustedData is now typed as SchemaMeta
```

### Signing a SchemaMeta as JWS

```typescript
import { ES256 } from '@owf/crypto';
import { signSchemaMeta, schemaMeta, schemaURI } from '@owf/eudi-attestation-schema';

const { privateKey } = await ES256.generateKeyPair();
const signer = await ES256.getSigner(privateKey);

const meta = schemaMeta()
  .version('1.0.0')
  .rulebookURI('https://example.com/rulebook.md')
  .attestationLoS('iso_18045_basic')
  .bindingType('key')
  .addSchemaURI(
    schemaURI()
      .format('dc+sd-jwt')
      .uri('https://example.com/schema.json')
      .meta({ vct: 'eu.example.gym-membership.1' })
      .build()
  )
  .build();

const signed = await signSchemaMeta({
  schemaMeta: meta,
  keyId: 'catalog-signer-2025',
  certificates: [pemCertificate],
  signer,
});

console.log(signed.jws); // Compact JWS string
console.log(signed.iat); // Issued-at timestamp (epoch seconds)
```

### Verifying a Signed SchemaMeta

```typescript
import { ES256 } from '@owf/crypto';
import { verifySchemaMeta } from '@owf/eudi-attestation-schema';

const verifier = await ES256.getVerifier(publicKey);

const { header, payload, iat } = await verifySchemaMeta({
  jws: signed.jws,
  verifier,
});

console.log(payload.version); // '1.0.0'
console.log(header.kid);      // 'catalog-signer-2025'
```

### Verify, Resolve Referenced Schemas, and Build DCQL

```typescript
import { ES256 } from '@owf/crypto';
import {
  verifyResolveAndBuildDcql,
} from '@owf/eudi-attestation-schema';

const verifier = await ES256.getVerifier(publicKey);

const result = await verifyResolveAndBuildDcql({
  jws: signed.jws,
  verifier,
  selectedFormats: ['dc+sd-jwt', 'mso_mdoc'],
  resolve: async (uri) => {
    const response = await fetch(uri);
    const content = await response.text();
    return { content, contentType: response.headers.get('content-type') ?? undefined };
  },
  verifyIntegrity: true,
  includeTrustedAuthorities: true,
  idPrefix: 'credential',
});

console.log(result.verified.payload.version);
console.log(result.resolvedReferences.length);
console.log(result.dcql.credentials);
```

Integrity notes:

- `verifyIntegrity` supports SRI digests with `sha256`, `sha384`, and `sha512`.
- Integrity validation hashes UTF-8 bytes of the resolver content.
- If resolver content is an object (not a string), integrity is computed over `JSON.stringify(content)`.

### DCQL claims from referenced JSON Schemas

When a resolved schema document contains a JSON Schema with a `properties` object, `verifyResolveAndBuildDcql` (and `buildDcqlFromSchemaMeta` when `resolvedReferences` are provided) automatically populates the `claims` array of each DCQL credential with a path entry for every defined property.

Given a referenced schema document such as:

```json
{
  "type": "object",
  "properties": {
    "given_name": { "type": "string" },
    "family_name": { "type": "string" },
    "address": {
      "type": "object",
      "properties": {
        "street_address": { "type": "string" },
        "country": { "type": "string" }
      }
    },
    "nationalities": {
      "type": "array",
      "items": { "type": "string" }
    }
  }
}
```

The resulting DCQL credential will contain:

```json
{
  "id": "credential-1",
  "format": "dc+sd-jwt",
  "meta": { "vct_values": ["eu.europa.ec.eudi.pid.1"] },
  "claims": [
    { "path": ["given_name"] },
    { "path": ["family_name"] },
    { "path": ["address", "street_address"] },
    { "path": ["address", "country"] },
    { "path": ["nationalities"] }
  ]
}
```

Claim extraction rules:

- **Primitive properties** (`string`, `number`, `boolean`, …) produce a single-element path.
- **Nested object properties** are recursed into; each leaf produces a multi-element path.
- **Array properties with primitive items** produce a single path entry for the array field itself.
- **Array properties with object or array items** are recursed into with a `null` wildcard appended to the path per the DCQL spec.
- Combinator keywords (`allOf`, `anyOf`, `oneOf`) are merged transparently.
- Duplicate paths across combinators are deduplicated deterministically.
- If no `parsedSchema` is available for a resolved reference, no `claims` key is added to the credential.

## SchemaURI `meta` Requirements

`SchemaURI` uses `formatIdentifier` as a discriminator, and the `meta` object is validated per format.

| `formatIdentifier` | Required `meta` shape | Notes |
|---|---|---|
| `dc+sd-jwt` | `{ vct: string }` | `vct` is required and must be a non-empty string |
| `mso_mdoc` | `{ doctype_value: string }` | `doctype_value` is required and must be a non-empty string |
| `jwt_vc_json` | `{}` | No format-specific fields are currently required |
| `jwt_vc_json-ld` | `{}` | No format-specific fields are currently required |
| `ldp_vc` | `{}` | No format-specific fields are currently required |

Example with multiple formats:

```typescript
import { schemaMeta, schemaURI } from '@owf/eudi-attestation-schema';

const meta = schemaMeta()
  .version('1.0.0')
  .rulebookURI('https://example.com/rulebook.md')
  .attestationLoS('iso_18045_basic')
  .bindingType('key')
  .addSchemaURI(
    schemaURI()
      .format('dc+sd-jwt')
      .uri('https://example.com/schemas/pid.sd-jwt.json')
      .meta({ vct: 'eu.europa.ec.eudi.pid.1' })
      .build()
  )
  .addSchemaURI(
    schemaURI()
      .format('mso_mdoc')
      .uri('https://example.com/schemas/pid.mdoc.json')
      .meta({ doctype_value: 'org.iso.18013.5.1.mDL' })
      .build()
  )
  .build();
```

## Data Model

### SchemaMeta (Main Class)

| Field | Required | Type | Description |
|---|---|---|---|
| `id` | No | `string` | Unique identifier for the attestation schema |
| `iat` | No | `number` | Issued-at timestamp (epoch seconds), typically set when signing |
| `version` | Yes | `string` | Schema version (SemVer) |
| `rulebookURI` | Yes | `string` (URL) | URI of the Attestation Rulebook |
| `rulebookIntegrity` | No | `string` | W3C SRI integrity metadata for the rulebook |
| `trustedAuthorities` | No | `TrustAuthority[]` | Trust anchors for attestation issuers |
| `attestationLoS` | Yes | `AttestationLoS` | Level of security |
| `bindingType` | Yes | `BindingType` | Cryptographic binding type |
| `schemaURIs` | Yes | `SchemaURI[]` | Schema URIs per format |

### SchemaURI

| Field | Required | Type | Description |
|---|---|---|---|
| `formatIdentifier` | Yes | `AttestationFormat` | Format discriminator (`dc+sd-jwt`, `mso_mdoc`, `jwt_vc_json`, `jwt_vc_json-ld`, `ldp_vc`) |
| `uri` | Yes | `string` (URL) | URI of the format-specific schema |
| `integrity` | No | `string` | W3C SRI integrity metadata for the referenced schema |
| `meta` | Yes | format-specific object | Credential-type metadata required by the selected format |

### Enumerations

**AttestationFormat**: `dc+sd-jwt`, `mso_mdoc`, `jwt_vc_json`, `jwt_vc_json-ld`, `ldp_vc`

**AttestationLoS**: `iso_18045_high`, `iso_18045_moderate`, `iso_18045_enhanced-basic`, `iso_18045_basic`

**BindingType**: `claim`, `key`, `biometric`, `none`

**FrameworkType**: `aki`, `etsi_tl`, `openid_federation`

## License

Apache-2.0
