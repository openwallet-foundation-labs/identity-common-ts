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
      .verificationMethod({
        type: 'X509Certificate',
        x509Certificate: 'MIIBczCCARmgAwIBAgIUZt2jkmAgIIiw/wpvJU/4yL7ek/YwCgYIKoZIzj0EAwIw',
      })
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
  .id('https://example.com/attestations/gym-membership-card')
  .version('1.0.0')
  .rulebookURI('https://example.com/rulebook.md')
  .rulebookIntegrity('sha256-cJe/IG7DijmXd2FpecyWJVnZ9EuKKprly5auxGm1uIw=')
  .attestationLoS('iso_18045_basic')
  .bindingType('key')
  .addSchemaURI(
    schemaURI()
      .format('dc+sd-jwt')
      .uri('https://example.com/schema.json')
      .integrity('sha256-M8H+reBt9Nr/s8CRicJrthAnk7UdWyTyONW0N8Z/Axw=')
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

- `verifyIntegrity` defaults to `true` and supports SRI digests with `sha256`.
- SRI is defined over the bytes as transferred, so `resolve` must return the response body as a `string` or `Uint8Array`. Returning already-parsed content throws unless `verifyIntegrity` is `false`.
- The same rule applies to documents reached through `extends`.

### SD-JWT VC Type Metadata

A `dc+sd-jwt` reference resolves to an [SD-JWT VC Type Metadata](https://www.ietf.org/archive/id/draft-ietf-oauth-sd-jwt-vc-18.html#name-sd-jwt-vc-type-metadata) document rather than to a bare JSON Schema:

```json
{
  "vct": "https://example.com/credentials/education",
  "extends": "https://example.com/credentials/base",
  "extends#integrity": "sha256-…",
  "claims": [
    { "path": ["given_name"], "sd": "allowed" },
    { "path": ["address", "country"], "sd": "always" },
    { "path": ["degrees", null, "type"] }
  ]
}
```

`resolveSchemaReferences` handles this automatically:

- The document is validated against the canonical `TypeMetadataFormatSchema` from `@sd-jwt/sd-jwt-vc`. Unknown members are preserved.
- Its `vct` is cross-checked against `meta.vct` from the catalogue entry; a mismatch throws.
- The `extends` chain is followed and merged, with the extending document winning and claims merged per path. `extends#integrity` is verified on each hop. Cycles throw, and `maxExtendsDepth` (default 10) bounds the chain.
- The merged document is available as `resolvedReference.typeMetadata`; Type Metadata itself does not contain a JSON Schema.

A reference that is a plain JSON Schema (no `vct` member) is still supported and behaves as before.

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

Every generated `path` is a DCQL claims path pointer: a non-empty array of strings, `null`s and non-negative integers, where a string selects the member with that key of an object, a non-negative integer selects the element at that index of an array, and `null` selects all elements of an array.

Claim extraction rules:

When a resolved reference carries Type Metadata with a non-empty `claims` array, those paths are used verbatim — Type Metadata states every claim as a claims path pointer already, so nothing has to be inferred. The rules below apply only when claims are derived from a JSON Schema instead.

- **Primitive properties** (`string`, `number`, `boolean`, …) produce a single-element path.
- **Nested object properties** are recursed into; each leaf produces a multi-element path.
- **Array properties with primitive items** produce a single path entry for the array field itself.
- **Array properties with object or array items** are recursed into with a `null` wildcard appended to the path.
- **Tuple-typed array properties** (a non-empty `prefixItems`, or the array form of `items`) produce one path per position, addressed by its non-negative index — for example `{ "path": ["coordinates", 0] }`. A rest schema next to those positions (`items` alongside `prefixItems`, or `additionalItems`) is skipped, because a claims path pointer cannot address every index from a position onwards.
- Combinator keywords (`allOf`, `anyOf`, `oneOf`) are merged transparently.
- Duplicate paths across combinators are deduplicated deterministically.
- If no `parsedSchema` is available for a resolved reference, no `claims` key is added to the credential.

### Issuance Profile and OID4VCI Issuer Metadata

A catalogue entry may carry an optional `issuanceProfile` describing the policy constraints an issuer of this attestation type must satisfy. Every member is an **allowed set or a bound, not a deployment value**: the catalogue narrows the space, and each issuer picks a conformant point inside it.

```typescript
import { schemaMeta, schemaURI } from '@owf/eudi-attestation-schema';

const meta = schemaMeta()
  // …required fields…
  .issuanceProfile({
    credentialSigningAlgValuesSupported: ['ES256', 'ES384'],
    cryptographicBindingMethodsSupported: ['jwk'],
    proofTypesSupported: { jwt: { proof_signing_alg_values_supported: ['ES256'] } },
    keyAttestationRequired: true,
    statusMechanism: { type: 'token_status_list', required: true },
    maxValidityPeriod: 7776000,
    batchIssuanceAllowed: false,
  })
  .build();
```

A prospective issuer can derive an OID4VCI `credential_configurations_supported` entry from the catalogue entry rather than copying another issuer's published metadata:

```typescript
import { buildCredentialConfigurationTemplate } from '@owf/eudi-attestation-schema';

const template = buildCredentialConfigurationTemplate({
  schemaMeta: meta,
  format: 'dc+sd-jwt',
  resolvedReferences, // optional, populates `claims`
});

console.log(template.credentialConfigurationId); // 'eu.europa.ec.eudi.pid.1'
console.log(template.credentialConfiguration);   // type- and policy-determined members only
console.log(template.deploymentFields);          // members the issuer must supply itself
```

And a wallet, auditor, or scheme owner can check a published metadata document against the catalogue entry:

```typescript
import { validateIssuerMetadataAgainstProfile } from '@owf/eudi-attestation-schema';

const result = validateIssuerMetadataAgainstProfile({
  issuerMetadata, // fetched from {credential_issuer}/.well-known/openid-credential-issuer
  schemaMeta: meta,
  format: 'dc+sd-jwt',
});

if (!result.valid) {
  console.error(result.errors);
}
```

Scope notes:

- Deployment-specific members (`credential_issuer`, `credential_endpoint`, `authorization_servers`, `scope`, `display`) are never emitted by the template and never checked.
- `statusMechanism` and `maxValidityPeriod` have no expression in issuer metadata and are therefore not validated.
- Technical conformance is not authorisation to issue — that remains governed by the trust list referenced in `trustedAuthorities`.

## SchemaURI `meta` Requirements

`SchemaURI` uses `formatIdentifier` as a discriminator, and the `meta` object is validated per format.

| `formatIdentifier` | Required `meta` shape | Notes |
|---|---|---|
| `dc+sd-jwt` | `{ vct: string }` | `vct` is required and must be a non-empty string, and must match the `vct` of the resolved Type Metadata document |
| `mso_mdoc` | `{ doctype_value: string }` | `doctype_value` is required and must be a non-empty string |

Example with multiple formats:

```typescript
import { schemaMeta, schemaURI } from '@owf/eudi-attestation-schema';

const meta = schemaMeta()
  .id('https://example.com/attestations/pid')
  .version('1.0.0')
  .rulebookURI('https://example.com/rulebook.md')
  .rulebookIntegrity('sha256-cJe/IG7DijmXd2FpecyWJVnZ9EuKKprly5auxGm1uIw=')
  .attestationLoS('iso_18045_basic')
  .bindingType('key')
  .addSchemaURI(
    schemaURI()
      .format('dc+sd-jwt')
      .uri('https://example.com/schemas/pid.sd-jwt.json')
      .integrity('sha256-M8H+reBt9Nr/s8CRicJrthAnk7UdWyTyONW0N8Z/Axw=')
      .meta({ vct: 'eu.europa.ec.eudi.pid.1' })
      .build()
  )
  .addSchemaURI(
    schemaURI()
      .format('mso_mdoc')
      .uri('https://example.com/schemas/pid.mdoc.json')
      .integrity('sha256-M8H+reBt9Nr/s8CRicJrthAnk7UdWyTyONW0N8Z/Axw=')
      .meta({ doctype_value: 'org.iso.18013.5.1.mDL' })
      .build()
  )
  .build();
```

## Data Model

### SchemaMeta (Main Class)

| Field | Required | Type | Description |
|---|---|---|---|
| `id` | Yes | `string` (URL) | Unique identifier for the attestation schema |
| `iat` | No | `number` (integer) | JWT NumericDate (epoch seconds), typically set when signing |
| `version` | Yes | `string` | Schema version (SemVer) |
| `rulebookURI` | Yes | `string` (URL) | URI of the Attestation Rulebook |
| `rulebookIntegrity` | Yes | `string` | Required W3C SRI sha256 integrity metadata for the rulebook |
| `trustedAuthorities` | No | `TrustAuthority[]` | Trust anchors for attestation issuers |
| `attestationLoS` | Yes | `AttestationLoS` | Level of security |
| `bindingType` | Yes | `BindingType` | Cryptographic binding type |
| `schemaURIs` | Yes | `SchemaURI[]` | Schema URIs per format |
| `issuanceProfile` | No | `IssuanceProfile` | Policy constraints a conformant issuer must satisfy |

### IssuanceProfile

All members are optional — a catalogue entry that omits the profile simply expresses no policy constraint.

| Field | Type | Description |
|---|---|---|
| `credentialSigningAlgValuesSupported` | `string[]` | Allowed credential signing algorithms |
| `cryptographicBindingMethodsSupported` | `string[]` | Allowed binding methods (`jwk`, `cose_key`, …) |
| `proofTypesSupported` | `Record<string, { proof_signing_alg_values_supported: string[] }>` | Allowed proof types and their algorithms |
| `keyAttestationRequired` | `boolean` | Whether issuers must require key attestation |
| `statusMechanism` | `{ type: 'token_status_list'; required: boolean }` | Required status mechanism |
| `maxValidityPeriod` | `number` | Upper bound on credential validity, in seconds |
| `batchIssuanceAllowed` | `boolean` | Whether batch issuance is permitted |

A profile must not declare `cryptographicBindingMethodsSupported` or `proofTypesSupported` when `bindingType` is `none`.

### SchemaURI

| Field | Required | Type | Description |
|---|---|---|---|
| `formatIdentifier` | Yes | `AttestationFormat` | Format discriminator (`dc+sd-jwt`, `mso_mdoc`) |
| `uri` | Yes | `string` (URL) | URI of the format-specific schema |
| `integrity` | Yes | `string` | Required W3C SRI sha256 integrity metadata for the referenced schema |
| `meta` | Yes | format-specific object | Credential-type metadata required by the selected format |

### TrustAuthority

| Field | Required | Type | Description |
|---|---|---|---|
| `frameworkType` | Yes | `FrameworkType` | Trust framework discriminator (`etsi_tl`) |
| `value` | Yes | `string` | URI pointing to the trust list |
| `verificationMethod` | Yes | object | Verification material for the trust list signature |

#### TrustAuthority.verificationMethod

| Field | Required | Type | Description |
|---|---|---|---|
| `type` | Yes | `'X509Certificate'` | Verification method type |
| `x509Certificate` | Yes | `string` | Base64-encoded DER X.509 certificate |

### Enumerations

**AttestationFormat**: `dc+sd-jwt`, `mso_mdoc`

**AttestationLoS**: `iso_18045_high`, `iso_18045_moderate`, `iso_18045_enhanced-basic`, `iso_18045_basic`

**BindingType**: `claim`, `key`, `biometric`, `none`

**FrameworkType**: `etsi_tl`

## License

Apache-2.0
