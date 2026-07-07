# @owf/eudi-wrprc

[![npm version](https://img.shields.io/npm/v/@owf/eudi-wrprc)](https://npmjs.com/package/@owf/eudi-wrprc)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://github.com/openwallet-foundation-labs/identity-common-ts/blob/main/LICENSE)

Implementation of **ETSI TS 119 475 v1.2.1** - Wallet-Relying Party Registration Certificates (WRPRC) for [Identity Common TypeScript](https://github.com/openwallet-foundation-labs/identity-common-ts).

**Info**
The `provides_attestations` field in the WRPRC payload currently supports either an array of strings (URIs) or an array of Credential objects. This allows compatibility while ETSI TS 119 475 evolves.

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

### Signing a WRPRC

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
```

## ETSI TS 119 475 Compliance

This implementation follows ETSI TS 119 475 v1.2.1 requirements:

- **GEN-5.2.2**: JWT/CWT headers with `typ: "rc-wrp+jwt"` or `typ: "rc-wrp+cwt"`
- **GEN-5.2.4-03**: At least one entitlement must be specified
- **GEN-5.2.4-04**: Sub-entitlements require the base entitlement
- **GEN-5.2.4-05**: Attestation providers should specify `provides_attestations`

### Semantic Identifiers

Subject identifiers (`sub`) follow ETSI EN 319 412-1:

| Type | Prefix | Country | Example |
|------|--------|---------|---------|
| LEI | `LEI` | `XG` | `LEIXG-529900T8BM49AURSDO55` |
| VAT | `VAT` | 2-letter | `VATDE-123456789` |
| TIN | `TIN` | 2-letter | `TINIT-RSSMRA85T10A562S` |
| NTR | `NTR` | 2-letter | `NTRNL-12345678` |
| PAS | `PAS` | 2-letter | `PASDE-C01X00T47` |
| IDC | `IDC` | 2-letter | `IDCIT-AX1234567` |

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

### Signer

- `signWRPRC(options)` - Sign a WRPRC payload to JWT
- `decodeWRPRC(jws)` - Decode a signed WRPRC
- `parseWRPRC(jws)` - Parse without validation

## Contributing

See the [Contributing Guide](https://github.com/openwallet-foundation-labs/identity-common-ts/blob/main/CONTRIBUTING.md) for details on how to contribute to this project.

## License

This project is licensed under the [Apache License Version 2.0](https://github.com/openwallet-foundation-labs/identity-common-ts/blob/main/LICENSE) (Apache-2.0).
