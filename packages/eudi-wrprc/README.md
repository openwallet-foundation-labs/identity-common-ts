# @owf/eudi-wrprc

[![npm version](https://img.shields.io/npm/v/@owf/eudi-wrprc)](https://npmjs.com/package/@owf/eudi-wrprc)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://github.com/openwallet-foundation-labs/identity-common-ts/blob/main/LICENSE)

Implementation of **ETSI TS 119 475 v1.2.1** - Wallet-Relying Party Registration Certificates (WRPRC) for [Identity Common TypeScript](https://github.com/openwallet-foundation-labs/identity-common-ts).

## Spec fidelity

This library follows ETSI TS 119 475 v1.2.1 **literally**, including its known editorial defects. The specification is referenced by the eIDAS 2 implementing acts, and other SDKs implement it as written, so reproducing it verbatim is what makes WRPRCs interoperable. Where the text is inconsistent, the **normative tables in clause 5** take precedence over the informative Annex C example.

Known defects that this library reproduces on purpose:

| Where | What the spec says | Note |
|-------|--------------------|------|
| Tables 8 and 9, Annex B.2.9 | The array of claim queries inside a `Credential` is named `claim` (singular) | Reads as a typo for `claims`, but it is consistent across the normative tables, Annex B and the Annex C example, so `claim` is emitted and accepted |
| Table 8 | `provides_attestations` holds `Credential` objects | A later edition is expected to allow an array of URLs pointing at the machine-readable scheme of each attestation, which carries more than the `Credential` object does. URLs are accepted on input; objects are emitted by default |
| Table 10 vs. Annex C | Table 10 names the intermediary common name `sname`; the Annex C example uses `name` | Table 10 is normative, so `sname` is used |
| Tables 5 and 6 | The header lists only `typ`, `alg` and `x5c` / `x5chain`, and the Annex C example header shows nothing else | Table 5 is a minimum set. GEN-5.2.1-04 additionally requires a JAdES B-B signature, whose protected header must carry `iat` as the claimed signing time, so signed WRPRCs have one |
| Table 7 | The payload has no unique identifier for the certificate | An optional `jti` (RFC 7519) is accepted and can be set through the builder, but is never required |

When ETSI publishes a corrected edition, these names will be updated in a major release rather than silently diverging from the current text.

### Reading and writing the anticipated corrections

Parsing is deliberately more liberal than writing. `claims`, `intermediary.name`, and a `provides_attestations` array of scheme URLs are all accepted on input and normalized to the shape above, so certificates produced by an SDK that already applies the corrections still validate.

Writing stays on the published edition unless you ask for otherwise:

```typescript
import { signWRPRC, WRPRC_DIALECTS } from '@owf/eudi-wrprc'

const signed = await signWRPRC({
  payload,
  certificates: [certificatePEM],
  signer,
  dialect: WRPRC_DIALECTS.DRAFT, // emits claims and intermediary.name
})
```

`WRPRC_DIALECTS.DRAFT` is **unstable**. No published edition defines it, so a certificate emitted this way may match neither the current specification nor its eventual correction. Leave the default in place unless you are testing against a counterpart that has already moved.

The dialect covers the two renames only. It does not touch `provides_attestations`, because a scheme URL cannot be derived from a `Credential` object: choose that form when building the payload instead.

`toWRPRCDialect(payload, dialect)` and `normalizeWRPRCPayload(value)` expose the same mapping if you need it outside the signer.

## Overview

This package provides:

- **Zod schemas** for validating WRPRC payloads and headers
- **TypeScript types** derived from the schemas
- **Entitlement constants** per ETSI TS 119 475 Annex A
- **Fluent builder API** for creating WRPRC payloads
- **Validators** implementing ETSI requirements
- **Signer** for creating signed JWT WRPRCs

## Installation

```bash
# Using npm
npm install @owf/eudi-wrprc

# Using pnpm
pnpm add @owf/eudi-wrprc

# Using yarn
yarn add @owf/eudi-wrprc
```

## Usage

### Creating a WRPRC with the Fluent Builder

```typescript
import { wrprc, WRP_ENTITLEMENTS } from '@owf/eudi-wrprc'

const payload = wrprc()
  .name('Example Service')
  .legalName('Example Inc.')
  .identifier('LEIXG-529900T8BM49AURSDO55')
  .country('DE')
  .registryUri('https://registry.example.com/api')
  .addEntitlement(WRP_ENTITLEMENTS.SERVICE_PROVIDER)
  .addEntitlement(WRP_ENTITLEMENTS.QEAA_PROVIDER)
  .privacyPolicy('https://example.com/privacy')
  .build()
```

### Creating a WRPRC for a Natural Person

```typescript
import { wrprc, WRP_ENTITLEMENTS } from '@owf/eudi-wrprc'

const payload = wrprc()
  .name('Self-Employed Consultant')
  .givenName('Maria')
  .familyName('Rossi')
  .identifier('TINIT-RSSMRA85T10A562S')
  .country('IT')
  .registryUri('https://registry.example.it/api')
  .addEntitlement(WRP_ENTITLEMENTS.SERVICE_PROVIDER)
  .build()
```

### Using Factory Functions

```typescript
import { createLegalPersonWRPRC, WRP_ENTITLEMENTS } from '@owf/eudi-wrprc'

const payload = createLegalPersonWRPRC({
  name: 'Example Service',
  legalName: 'Example Inc.',
  identifier: 'LEIXG-529900T8BM49AURSDO55',
  country: 'DE',
  registryUri: 'https://registry.example.com/api',
  entitlements: [WRP_ENTITLEMENTS.SERVICE_PROVIDER],
})
```

### Specifying Credentials to Request

```typescript
import { wrprc, credential, WRP_ENTITLEMENTS } from '@owf/eudi-wrprc'

const payload = wrprc()
  .name('Verification Service')
  .legalName('VerifyCo Ltd.')
  .identifier('LEIXG-123456789ABCDEFGH')
  .country('NL')
  .registryUri('https://registry.example.nl/api')
  .addEntitlement(WRP_ENTITLEMENTS.SERVICE_PROVIDER)
  .addCredential(
    credential()
      .format('dc+sd-jwt')
      .meta({ vct: 'https://example.com/credentials/identity' })
      .addPathClaim('given_name')
      .addPathClaim('family_name')
      .build()
  )
  .build()
```

### Declaring Provided Attestations

Attestation providers declare what they issue with `provides_attestations` (GEN-5.2.4-05). ETSI TS 119 475 v1.2.1 defines this as `Credential` objects:

```typescript
import { wrprc, credential, WRP_ENTITLEMENTS } from '@owf/eudi-wrprc'

const payload = wrprc()
  .name('Attestation Provider')
  .legalName('Issuer GmbH')
  .identifier('LEIXG-529900T8BM49AURSDO55')
  .country('DE')
  .registryUri('https://registry.example.com/api')
  .addEntitlement(WRP_ENTITLEMENTS.NON_Q_EAA_PROVIDER)
  .addProvidedAttestation(
    credential().sdJwtMeta(['https://example.com/attestations/age_over_18']).build()
  )
  .build()
```

The same method also accepts a URL pointing at the attestation's machine-readable scheme, the form anticipated for a later edition:

```typescript
  .addProvidedAttestation('https://catalogue.europa.eu/schemes/age_over_18')
```

A payload must use one form throughout; mixing objects and URLs throws.

### Signing a WRPRC

GEN-5.2.1-04 requires the JWT to carry a JAdES signature with the B-B profile of ETSI TS 119 182-1. `signWRPRC` builds one through [`@owf/eudi-jades`](../eudi-jades), so the protected header holds `typ`, `alg`, the `x5c` certificate chain and the `iat` claimed signing time. `decodeWRPRC` rejects tokens that do not meet the B-B profile.

```typescript
import { signWRPRC, wrprc, WRP_ENTITLEMENTS } from '@owf/eudi-wrprc'
import { ES256 } from '@owf/crypto'

const payload = wrprc()
  .name('Example Service')
  .legalName('Example Inc.')
  .identifier('LEIXG-529900T8BM49AURSDO55')
  .country('DE')
  .registryUri('https://registry.example.com/api')
  .addEntitlement(WRP_ENTITLEMENTS.SERVICE_PROVIDER)
  .build()

const { privateKey } = await ES256.generateKeyPair()
const signer = await ES256.getSigner(privateKey)

// PEM-encoded x509 certificate chain (leaf first)
const certificatePEM = `-----BEGIN CERTIFICATE-----
...
-----END CERTIFICATE-----`

const signed = await signWRPRC({
  payload,
  algorithm: 'ES256',
  certificates: [certificatePEM],
  signer,
})

console.log(signed.jws) // Compact JWS string
```

Pass `signingTime` to pin the claimed signing time; it defaults to now.

### Decoding a WRPRC

```typescript
import { decodeWRPRC } from '@owf/eudi-wrprc'

const jwsString = 'eyJ0eXAiOiJyYy13cnArand0Ii...'
const decoded = decodeWRPRC(jwsString)

console.log(decoded.header)  // { typ: 'rc-wrp+jwt', alg: 'ES256', ... }
console.log(decoded.payload) // { name: '...', sub: '...', ... }
```

### Validating a WRPRC

```typescript
import { validateWRPRCPayload } from '@owf/eudi-wrprc'

const result = validateWRPRCPayload(payload)

if (result.valid) {
  console.log('WRPRC is valid')
} else {
  console.log('Errors:', result.errors)
}

// Warnings are returned even for valid payloads
if (result.warnings.length > 0) {
  console.log('Warnings:', result.warnings)
}
```

### Entitlement Constants

The package exports all entitlement URIs from ETSI TS 119 475 Annex A:

```typescript
import { WRP_ENTITLEMENTS, PSP_SUB_ENTITLEMENTS } from '@owf/eudi-wrprc'

// Main entitlements
WRP_ENTITLEMENTS.SERVICE_PROVIDER           // Basic service provider
WRP_ENTITLEMENTS.QEAA_PROVIDER              // Qualified EAA provider
WRP_ENTITLEMENTS.NON_Q_EAA_PROVIDER         // Non-qualified EAA provider
WRP_ENTITLEMENTS.PUB_EAA_PROVIDER           // Public EAA provider
WRP_ENTITLEMENTS.PID_PROVIDER               // Person Identification Data provider
WRP_ENTITLEMENTS.QCERT_FOR_ESEAL_PROVIDER   // Qualified cert for e-seal issuer
WRP_ENTITLEMENTS.QCERT_FOR_ESIG_PROVIDER    // Qualified cert for e-sig issuer
WRP_ENTITLEMENTS.RQSEALCDS_PROVIDER         // Remote qualified seal creation device
WRP_ENTITLEMENTS.RQSIGCDS_PROVIDER          // Remote qualified sig creation device
WRP_ENTITLEMENTS.ESIG_ESEAL_CREATION_PROVIDER // Non-qualified e-sig/seal creation

// PSP sub-entitlements (require SERVICE_PROVIDER)
PSP_SUB_ENTITLEMENTS.PAYMENT_INITIATION     // Payment initiation services
PSP_SUB_ENTITLEMENTS.ACCOUNT_INFORMATION    // Account information services
PSP_SUB_ENTITLEMENTS.ACCOUNT_SERVICING      // Account servicing provider
PSP_SUB_ENTITLEMENTS.CARD_BASED             // Card-based payment instruments
PSP_SUB_ENTITLEMENTS.UNSPECIFIED            // Unspecified payment service provider
```

## ETSI TS 119 475 Compliance

This implementation follows ETSI TS 119 475 v1.2.1 requirements:

- **GEN-5.2.1-04**: JAdES B-B signature (ETSI TS 119 182-1), with the JAdES B-B algorithm set (`ES*`, `PS*`, `RS*`, `EdDSA`)
- **GEN-5.2.2 / GEN-5.2.3**: JWT/CWT headers with `typ: "rc-wrp+jwt"` or `typ: "rc-wrp+cwt"`
- **GEN-5.2.4-03**: At least one entitlement must be specified
- **GEN-5.2.4-04**: Sub-entitlements require the base entitlement
- **GEN-5.2.4-05**: Attestation providers should specify `provides_attestations`
- **GEN-5.2.4-06**: Service providers should specify `credentials` and `purpose`
- **GEN-5.2.4-08**: `exp` at most 12 months after `iat`
- **GEN-5.2.4-09**: Under intermediation, `act.sub` matches `intermediary.sub`

### Semantic Identifiers

Subject identifiers (`sub`) follow ETSI EN 319 412-1, with the type-to-prefix mapping of Table 2 (legal persons) and Table 4 (natural persons).

Legal persons (Table 2, EN 319 412-1 clause 5.1.4):

| Identifier type | Prefix | Example |
|-----------------|--------|---------|
| EORI-No | `EOR` | `EORDE-DE1234567890` |
| LEI | `LEI` | `LEIXG-529900T8BM49AURSDO55` |
| EUID | `NTR` | `NTRNL-12345678` |
| VATIN | `VAT` | `VATDE-123456789` |
| TIN | `VAT` | `VATDE-123456789` |
| Excise | `EXC` | `EXCDE-DE00012345678` |

Natural persons (Table 4, EN 319 412-1 clause 5.1.3):

| Identifier type | Prefix | Example |
|-----------------|--------|---------|
| VATIN / TIN | `TIN` | `TINIT-RSSMRA85T10A562S` |
| Passport number | `PAS` | `PASDE-C01X00T47` |
| Identity card number | `IDC` | `IDCIT-AX1234567` |
| National personal number | `PNO` | `PNOSE-197001019999` |

## Platform Support

This library is **platform agnostic** and works in:

- ✅ Node.js (>=20)
- ✅ Browsers (modern browsers with ES2020 support)
- ✅ React Native

## API Reference

### Schemas

- `WRPRCPayloadSchema` - Full WRPRC payload validation
- `WRPRCJWTHeaderSchema` - JWT header validation
- `WRPRCCWTHeaderSchema` - CWT header validation
- `CredentialSchema` - Credential specification validation
- `ClaimSchema` - Claim specification validation
- `MultiLangStringSchema` - Multilingual string validation

### Types

- `WRPRCPayload` - WRPRC payload type
- `WRPRCJWTHeader` - JWT header type
- `SignedWRPRC` - Signed WRPRC with JWS string
- `Credential` - Credential specification type
- `Claim` - Claim specification type

### Builders

- `WRPRCBuilder` - Fluent builder for WRPRC payloads
- `CredentialBuilder` - Fluent builder for credential specifications
- `wrprc()` - Factory function for WRPRCBuilder
- `credential()` - Factory function for CredentialBuilder

### Validators

- `validateWRPRCPayload(payload)` - Validate WRPRC payload
- `validateWRPRCJWTHeader(header)` - Validate JWT header
- `validateWRPRC(header, payload)` - Validate complete WRPRC
- `assertValidWRPRCPayload(payload)` - Assert or throw
- `parseWRPRCPayload(payload)` - Validate and return the canonical payload

### Dialects

- `WRPRC_DIALECTS` - Supported wire dialects
- `normalizeWRPRCPayload(value)` - Map either spelling to the published one
- `toWRPRCDialect(payload, dialect)` - Serialize a canonical payload in a dialect

### Signer

- `signWRPRC(options)` - Sign a WRPRC payload to JWT
- `decodeWRPRC(jws)` - Decode a signed WRPRC
- `parseWRPRC(jws)` - Parse without validation

## Contributing

See the [Contributing Guide](https://github.com/openwallet-foundation-labs/identity-common-ts/blob/main/CONTRIBUTING.md) for details on how to contribute to this project.

## License

This project is licensed under the [Apache License Version 2.0](https://github.com/openwallet-foundation-labs/identity-common-ts/blob/main/LICENSE) (Apache-2.0).
