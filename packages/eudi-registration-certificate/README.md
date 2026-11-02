# @owf/eudi-registration-certificate

[![npm version](https://img.shields.io/npm/v/@owf/eudi-registration-certificate)](https://npmjs.com/package/@owf/eudi-registration-certificate)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://github.com/openwallet-foundation-labs/identity-common-ts/blob/main/LICENSE)

Implementation of **ETSI TS 119 475 v1.2.1** - Wallet-Relying Party Registration Certificates (WRPRC) for [Identity Common TypeScript](https://github.com/openwallet-foundation-labs/identity-common-ts).

## Spec fidelity

This library follows ETSI TS 119 475 v1.2.1 **literally**, including its known editorial defects. The specification is referenced by the eIDAS 2 implementing acts, and other SDKs implement it as written, so reproducing it verbatim is what makes registration certificates interoperable. Where the text is inconsistent, the **normative tables in clause 5** take precedence over the informative Annex C example.

Known defects that this library reproduces on purpose:

| Where | What the spec says | Note |
|-------|--------------------|------|
| Tables 8 and 9, Annex B.2.9 | The array of claim queries inside a `Credential` is named `claim` (singular) | Reads as a typo for `claims`, but it is consistent across the normative tables, Annex B and the Annex C example, so `claim` is emitted and accepted |
| Table 8 | `provides_attestations` holds `Credential` objects with `format` and `meta` only | Claim queries are for requested credentials. Provided attestations describe what the WRP issues, so `claim` / `claims` is rejected there and wallets do not have to resolve external scheme documents to understand what is provided |
| Table 10 vs. Annex C | Table 10 names the intermediary common name `sname`; the Annex C example uses `name` | Table 10 is normative, so `sname` is used |
| Tables 5 and 6 | The header lists only `typ`, `alg` and `x5c` / `x5chain`, and the Annex C example header shows nothing else | Table 5 is a minimum set. GEN-5.2.1-04 additionally requires a JAdES B-B signature, whose protected header must carry `iat` as the claimed signing time, so signed registration certificates have one |
| Table 7 | The payload has no unique identifier for the certificate | An optional `jti` (RFC 7519) is accepted and can be set through the builder, but is never required |

When ETSI publishes a corrected edition, these names will be updated in a major release rather than silently diverging from the current text.

### Reading and writing the anticipated corrections

Parsing is deliberately more liberal than writing for the two field renames. `claims` and `intermediary.name` are accepted on input and normalized to the shape above, so certificates produced by an SDK that already applies those corrections still validate.

Writing stays on the published edition unless you ask for otherwise:

```typescript
import { signRegistrationCertificate, REGISTRATION_CERTIFICATE_DIALECTS } from '@owf/eudi-registration-certificate'

const signed = await signRegistrationCertificate({
  payload,
  accessCertificateSub,
  certificates: [certificatePEM],
  signer,
  dialect: REGISTRATION_CERTIFICATE_DIALECTS.DRAFT, // emits claims and intermediary.name
})
```

`REGISTRATION_CERTIFICATE_DIALECTS.DRAFT` is **unstable**. No published edition defines it, so a certificate emitted this way may match neither the current specification nor its eventual correction. Leave the default in place unless you are testing against a counterpart that has already moved.

The dialect covers the two renames only. It does not touch `provides_attestations`, which is always represented as `Credential` objects with `format` and `meta` only.

`toRegistrationCertificateDialect(payload, dialect)` and `normalizeRegistrationCertificatePayload(value)` expose the same mapping if you need it outside the signer.

## Overview

This package provides:

- **Zod schemas** for validating registration certificate payloads and headers
- **TypeScript types** derived from the schemas
- **Entitlement constants** per ETSI TS 119 475 Annex A
- **Fluent builder API** for creating registration certificate payloads
- **Validators** implementing ETSI requirements
- **Signer** for creating signed JWT registration certificates

## Installation

```bash
# Using npm
npm install @owf/eudi-registration-certificate

# Using pnpm
pnpm add @owf/eudi-registration-certificate

# Using yarn
yarn add @owf/eudi-registration-certificate
```

## Usage

### Creating a registration certificate with the Fluent Builder

```typescript
import { registrationCertificate, WRP_ENTITLEMENTS } from '@owf/eudi-registration-certificate'

const payload = registrationCertificate()
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

### Creating a registration certificate for a Natural Person

```typescript
import { registrationCertificate, WRP_ENTITLEMENTS } from '@owf/eudi-registration-certificate'

const payload = registrationCertificate()
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
import { createLegalPersonRegistrationCertificate, WRP_ENTITLEMENTS } from '@owf/eudi-registration-certificate'

const payload = createLegalPersonRegistrationCertificate({
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
import { registrationCertificate, credential, WRP_ENTITLEMENTS } from '@owf/eudi-registration-certificate'

const payload = registrationCertificate()
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

Attestation providers declare what they issue with `provides_attestations` (GEN-5.2.4-05). ETSI TS 119 475 v1.2.1 defines this as `Credential` objects containing `format` and `meta` only:

```typescript
import { registrationCertificate, credential, WRP_ENTITLEMENTS } from '@owf/eudi-registration-certificate'

const payload = registrationCertificate()
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

Scheme URLs are not accepted for `provides_attestations`: wallets should be able to inspect the declared credential format and metadata directly without resolving an external document first. Claim queries are not accepted either, because the WRP is declaring what it issues rather than what it requests.

### Signing a registration certificate

GEN-5.2.1-04 requires the JWT to carry a JAdES signature with the B-B profile of ETSI TS 119 182-1. `signRegistrationCertificate` builds one through [`@owf/eudi-jades`](../eudi-jades), so the protected header holds `typ`, `alg`, the `x5c` certificate chain and the `iat` claimed signing time. `decodeRegistrationCertificate` rejects tokens that do not meet the B-B profile.

```typescript
import { signRegistrationCertificate, registrationCertificate, WRP_ENTITLEMENTS } from '@owf/eudi-registration-certificate'
import { ES256 } from '@owf/crypto'

const payload = registrationCertificate()
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

const signed = await signRegistrationCertificate({
  payload,
  accessCertificateSub,
  algorithm: 'ES256',
  certificates: [certificatePEM],
  signer,
})

console.log(signed.jws) // Compact JWS string
```

Pass `signingTime` to pin the claimed signing time; it defaults to now.

### Decoding a registration certificate

```typescript
import { decodeRegistrationCertificate } from '@owf/eudi-registration-certificate'

const jwsString = 'eyJ0eXAiOiJyYy13cnArand0Ii...'
const decoded = decodeRegistrationCertificate(jwsString, accessCertificateSub)

console.log(decoded.header)  // { typ: 'rc-wrp+jwt', alg: 'ES256', ... }
console.log(decoded.payload) // { name: '...', sub: '...', ... }
```

### Validating a registration certificate

```typescript
import { validateRegistrationCertificatePayload } from '@owf/eudi-registration-certificate'

const result = validateRegistrationCertificatePayload(payload, accessCertificateSub)

console.log(result.valid ? 'Registration certificate is valid' : 'Registration certificate is invalid')

// Errors and warnings in one list; warnings are returned even for valid payloads
for (const issue of result.issues) {
  // e.g. error exp_too_late exp: exp must be at most 12 months after iat (GEN-5.2.4-08)
  console.log(issue.severity, issue.code, `${issue.path.join('.')}: ${issue.message}`)
}
```

`accessCertificateSub` is required for payload validation, parsing, signing, and decoding. It is compared with `intermediary.sub` when the registration certificate has an intermediary, and with `sub` otherwise.

Each issue has a `severity`, a `code` from `REGISTRATION_CERTIFICATE_VALIDATION_CODES` or, for schema issues, from `SCHEMA_VALIDATION_CODES` of `@owf/identity-common`, a `path` into the payload and, where a check has one, the ETSI TS 119 475 `requirement`. Checks that recur in other specifications use the codes of `VALIDATION_CODES` from `@owf/identity-common` and carry a typed `context`:

- `invalid_typ`, when the JWT header `typ` is not `rc-wrp+jwt`, with `expected` and `actual`;
- `expires_before_issued`, when `exp` is at or before `iat`, with `issuedAt` and `expiresAt`.

Checking the code, e.g. `issue.code === 'invalid_typ'`, narrows the `context` to the one of that code. `assertValidRegistrationCertificatePayload`, `parseRegistrationCertificatePayload` and `assertValidRegistrationCertificate` throw a `RegistrationCertificateValidationError` with the same `issues`. It extends `RegistrationCertificateError`, the error of the other failures.

### Checking a Request for Over-Asking

`checkOverAsking` compares the DCQL query of an OpenID4VP request with the `credentials` of the registration certificate, and reports every credential and claim the request asks for beyond the registration:

```typescript
import { checkOverAsking } from '@owf/eudi-registration-certificate'

const result = checkOverAsking(authorizationRequest.dcql_query, registrationCertificatePayload.credentials)

// The same { valid, issues } as validateRegistrationCertificatePayload: valid is false when any issue is an error
for (const issue of result.issues) {
  // e.g. error credentials.0.claims.1: Credential query pid asks for the claim ["birthdate"], which is not registered
  console.log(issue.severity, `${issue.path.join('.')}: ${issue.message}`)
}
```

- The query is parsed and validated with the [`dcql`](../dcql) library. A query it rejects gets its issues, at their location in the query and with a code of `DCQL_VALIDATION_CODES`, such as `duplicate_credential_query_id`, or a schema code, such as `missing`. A claims query without `path` (the `namespace` and `claim_name` form of earlier OpenID4VP drafts) gives an `invalid_query` issue.
- A requested credential needs a registered one of the same `format` whose `meta` it stays within: every requested `vct_values` or `type_values` entry is registered, and `doctype_value` is the same.
- A requested claim needs a registered claim with the same path or a parent path, as registering `address` covers `address.locality`. `null` in a registered path covers every array element. A registered claim with `values` only allows requests for some of these values.
- A credential query without `claims` asks for no selectively disclosable claims, so only its credential is checked.
- A registered credential without claims gives a warning for each credential query with claims, as the registration does not say which claims are allowed.

### Entitlement Constants

The package exports all entitlement URIs from ETSI TS 119 475 Annex A:

```typescript
import { WRP_ENTITLEMENTS, PSP_SUB_ENTITLEMENTS } from '@owf/eudi-registration-certificate'

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
- Under intermediation, `intermediary.sub` is checked against the supplied access-certificate subject

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

- `zRegistrationCertificatePayload` - Full registration certificate payload validation
- `zRegistrationCertificateJWTHeader` - JWT header validation
- `zRegistrationCertificateCWTHeader` - CWT header validation
- `zCredential` - Credential specification validation
- `zClaim` - Claim specification validation
- `zMultiLangString` - Multilingual string validation

### Types

- `RegistrationCertificatePayload` - Registration certificate payload type
- `RegistrationCertificateJWTHeader` - JWT header type
- `SignedRegistrationCertificate` - Signed registration certificate with JWS string
- `Credential` - Credential specification type
- `ProvidedAttestation` - Provided attestation credential type with `format` and `meta` only
- `Claim` - Claim specification type

### Builders

- `RegistrationCertificateBuilder` - Fluent builder for registration certificate payloads
- `CredentialBuilder` - Fluent builder for credential specifications
- `registrationCertificate()` - Factory function for RegistrationCertificateBuilder
- `credential()` - Factory function for CredentialBuilder

### Validators

- `validateRegistrationCertificatePayload(payload, accessCertificateSub)` - Validate payload and access-certificate identity
- `validateRegistrationCertificateJWTHeader(header)` - Validate JWT header
- `validateRegistrationCertificate(header, payload, accessCertificateSub)` - Validate complete registration certificate and access-certificate identity
- `assertValidRegistrationCertificatePayload(payload, accessCertificateSub)` - Assert or throw
- `parseRegistrationCertificatePayload(payload, accessCertificateSub)` - Validate and return the canonical payload

### Dialects

- `REGISTRATION_CERTIFICATE_DIALECTS` - Supported wire dialects
- `normalizeRegistrationCertificatePayload(value)` - Map either spelling to the published one
- `toRegistrationCertificateDialect(payload, dialect)` - Serialize a canonical payload in a dialect

### Signer

- `signRegistrationCertificate(options)` - Sign a registration certificate payload to JWT
- `decodeRegistrationCertificate(jws, accessCertificateSub)` - Decode and validate a signed registration certificate
- `parseRegistrationCertificate(jws)` - Parse without validation

## Contributing

See the [Contributing Guide](https://github.com/openwallet-foundation-labs/identity-common-ts/blob/main/CONTRIBUTING.md) for details on how to contribute to this project.

## License

This project is licensed under the [Apache License Version 2.0](https://github.com/openwallet-foundation-labs/identity-common-ts/blob/main/LICENSE) (Apache-2.0).
