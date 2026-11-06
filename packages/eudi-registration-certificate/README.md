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
| GEN-6.2.6.1-04 vs. Annex C | `idx` of the status is a numeric string, while the Annex C example and the Token Status List use an integer | Both are read, as a number. The builder writes an integer |
| Tables 6 to 10 | The payload fields have no CBOR labels for a CWT | A CWT carries `sub`, `exp`, `iat`, `jti` (as `cti`) and `status` under their registered CWT claim keys, and the other fields under their JSON name. The JSON names of the registered claims are read too |

When ETSI publishes a corrected edition, these names will be updated in a major release rather than silently diverging from the current text.

### Reading and writing the anticipated corrections

Parsing is deliberately more liberal than writing for the two field renames. `claims` and `intermediary.name` are accepted on input and normalized to the shape above, so certificates produced by an SDK that already applies those corrections still validate.

Writing stays on the published edition unless you ask for otherwise:

```typescript
import { signRegistrationCertificateJwt, REGISTRATION_CERTIFICATE_DIALECTS } from '@owf/eudi-registration-certificate'

const signed = await signRegistrationCertificateJwt({
  payload,
  accessCertificateSub,
  certificates: [certificatePEM],
  signJwsCallback,
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
- **Signer** for creating signed JWT and CWT registration certificates
- **Decoders** for registration certificates in mdoc and OpenID4VP requests
- **Verification** of a JWT or CWT registration certificate: signature, validity period and status

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

GEN-5.2.1-04 requires the JWT to carry a JAdES signature with the B-B profile of ETSI TS 119 182-1. `signRegistrationCertificateJwt` builds one through [`@owf/eudi-jades`](../eudi-jades), so the protected header holds `typ`, `alg`, the `x5c` certificate chain and the `iat` claimed signing time. The signature comes from a `SignJwsCallback` of [`@owf/jose`](../jose), which signs with the key of the first certificate. `decodeRegistrationCertificateJwt` rejects tokens that do not meet the B-B profile.

```typescript
import { signRegistrationCertificateJwt, registrationCertificate, WRP_ENTITLEMENTS } from '@owf/eudi-registration-certificate'
import { base64url } from '@owf/identity-common'
import type { SignJwsCallback } from '@owf/jose'

const payload = registrationCertificate()
  .name('Example Service')
  .legalName('Example Inc.')
  .identifier('LEIXG-529900T8BM49AURSDO55')
  .country('DE')
  .registryUri('https://registry.example.com/api')
  .addEntitlement(WRP_ENTITLEMENTS.SERVICE_PROVIDER)
  .build()

// `kms` stands in for your own key management
const signJwsCallback: SignJwsCallback = async (signer, { signingInputBytes }) => ({
  signature: base64url.encode(await kms.sign({ algorithm: signer.alg, data: signingInputBytes })),
  signerJwk: kms.publicJwk,
})

// PEM-encoded x509 certificate chain (leaf first)
const certificatePEM = `-----BEGIN CERTIFICATE-----
...
-----END CERTIFICATE-----`

const signed = await signRegistrationCertificateJwt({
  payload,
  accessCertificateSub,
  algorithm: 'ES256',
  certificates: [certificatePEM],
  signJwsCallback,
})

console.log(signed.jws) // Compact JWS string
```

Pass `signingTime` to pin the claimed signing time. It defaults to now.

### Decoding a registration certificate

```typescript
import { decodeRegistrationCertificateJwt } from '@owf/eudi-registration-certificate'

const jwsString = 'eyJ0eXAiOiJyYy13cnArand0Ii...'
const decoded = decodeRegistrationCertificateJwt(jwsString, accessCertificateSub)

console.log(decoded.header)  // { typ: 'rc-wrp+jwt', alg: 'ES256', ... }
console.log(decoded.payload) // { name: '...', sub: '...', ... }
```

### CWT registration certificates

`signRegistrationCertificateCwt` signs the payload as a CBOR map in a COSE_Sign1 (GEN-5.2.1-05). `sub` (2), `exp` (4), `iat` (6), `jti` (`cti`, 7, as UTF-8 bytes) and `status` (65535, Token Status List section 6.3) use their registered CWT claim keys, the other fields their JSON name. Its protected header holds `alg`, `typ` (`rc-wrp+cwt`) and the `x5chain`. The signature comes from a `signCoseCallback`, the `sign` of a `Sign1Context` of [`@owf/cose`](../cose):

```typescript
import { signRegistrationCertificateCwt, decodeRegistrationCertificateCwt } from '@owf/eudi-registration-certificate'

const signed = await signRegistrationCertificateCwt({
  payload,
  accessCertificateSub,
  certificates: [certificatePEM],
  signingKey,
  signCoseCallback: async ({ toBeSigned, key, algorithm }) => sign(toBeSigned, key, algorithm),
})

const decoded = decodeRegistrationCertificateCwt(signed.cwt, accessCertificateSub)
```

`payload` is a registration certificate payload, or its CBOR claims set, a `RegistrationCertificateCwtPayload`. Build that from a payload to extend or modify it before it is signed, as the claims set of `@owf/cose` allows:

```typescript
import { RegisteredCwtClaimKey } from '@owf/cose'
import { RegistrationCertificateCwt, RegistrationCertificateCwtPayload } from '@owf/eudi-registration-certificate'

const claimsSet = RegistrationCertificateCwtPayload.fromRegistrationCertificate(payload)
claimsSet.claims.set(RegisteredCwtClaimKey.Issuer, 'https://registrar.example')

const signed = await signRegistrationCertificateCwt({ payload: claimsSet, accessCertificateSub, certificates, signingKey, signCoseCallback })

// The CWT as a structure, with the claims set as signed
const { payload: signedClaimsSet } = RegistrationCertificateCwt.fromToken(signed.cwt)
```

`decodeRegistrationCertificateCwt` reads a tagged or untagged COSE_Sign1, and the header from the protected bucket only. Like the JWT decoder, it does not verify the signature: see [Verifying a registration certificate](#verifying-a-registration-certificate).

### Registration certificates in mdoc requests

An mdoc reader sends its registration certificate as the `euWrprc` byte string in the `requestInfo` of each `ItemsRequest` (ETSI TS 119 472-2 clause 5.3.2, as amended by CIR (EU) 2024/2982). `mdocRegistrationCertificateExtension` gives that entry for the `extensions` of `@owf/mdoc`:

```typescript
import { ItemsRequest } from '@owf/mdoc'
import { mdocRegistrationCertificateExtension } from '@owf/eudi-registration-certificate'

const itemsRequest = ItemsRequest.create({
  docType,
  namespaces,
  requestInfo: { extensions: { ...mdocRegistrationCertificateExtension(signed.cwt) } },
})
```

A wallet decodes it from the request, with the subject of the access certificate that signed `readerAuth`:

```typescript
import { decodeMdocRegistrationCertificate } from '@owf/eudi-registration-certificate'

const registrationCertificate = decodeMdocRegistrationCertificate(itemsRequest.requestInfo, accessCertificateSub)
```

It returns `undefined` when the request has none. The CIR asks for a CBOR-encoded registration certificate, but a JWT is decoded too. The CDDL of ETSI TS 119 472-2 spells the label `eUWrprc`, so that spelling is read as well.

### Registration certificates in OpenID4VP requests

A verifier sends its registration certificate as an element of `verifier_info` with `format` `registration_cert` (ETSI TS 119 472-2 clause 6.3.2.2). Only a JWT registration certificate is sent this way, as a CWT is for mdoc requests. `openid4vpRegistrationCertificateVerifierInfo` gives that element, with `data` base64url encoded, as OIDFVP-HAIP-COMMON-REQ-RO-16 asks, or as the compact serialization itself:

```typescript
import { openid4vpRegistrationCertificateVerifierInfo } from '@owf/eudi-registration-certificate'

const verifierInfo = [openid4vpRegistrationCertificateVerifierInfo(signed.jws)]

// The compact JWS itself as `data`
const compactVerifierInfo = [openid4vpRegistrationCertificateVerifierInfo(signed.jws, { encoding: 'compact' })]
```

A wallet decodes it with the subject of the access certificate that signed the request:

```typescript
import { decodeOpenid4vpRegistrationCertificate } from '@owf/eudi-registration-certificate'

const registrationCertificate = decodeOpenid4vpRegistrationCertificate(
  authorizationRequest.verifier_info,
  accessCertificateSub
)
```

`data` is read as a base64url encoded or a compact JWT, and anything else, a CWT included, is rejected. It returns `undefined` when `verifier_info` has no registration certificate, and rejects more than one, an element with `credential_ids` (RO-14) and `data` that is not a string.

### Verifying a registration certificate

`verifyRegistrationCertificate` verifies a JWT or CWT registration certificate completely:

1. The header and payload, as the decode functions check them.
2. The signature, and whether its signer is trusted, through your callbacks.
3. `iat` and `exp` against `now`, with a clock skew of 30 seconds, by [`@owf/jose`](../jose) for a JWT and [`@owf/cose`](../cose) for a CWT.
4. The status in the status list it references (clause 6.2.6), checked as the Token Status List describes: `typ`, the signature through the same callbacks, `sub` against the `uri`, `iat` and `exp`, and the status at `idx`.

A registration certificate without `status` is rejected, as REV-6.2.6.2-03 has every one reference its status list.

```typescript
import { verifyRegistrationCertificate } from '@owf/eudi-registration-certificate'

const verified = await verifyRegistrationCertificate({
  // a compact JWS, the bytes of a CWT, or what a decode function returned
  registrationCertificate,
  accessCertificateSub,
  callbacks: {
    // a `VerifyJwsCallback` of @owf/jose, for a registration certificate or status list in JWT format
    verifyJws: async (signer, { signingInputBytes, signature }) => verifyJwsWithTrustedRegistrar(signer, signingInputBytes, signature),
    // the same for a CWT: verify `signature` over `toBeVerified` with the key of the first certificate of `x5chain`
    verifyCose: async ({ x5chain, algorithm, toBeVerified, signature }) => verifyCoseWithTrustedRegistrar(x5chain, algorithm, toBeVerified, signature),
  },
})
```

The callbacks decide whether the certificate chain chains to a trusted registration certificate provider. The signer of a JWT registration certificate is always an `x5c` signer.

Both callbacks are required: a registration certificate and its status list can each be a JWT or a CWT.

Anything that does not verify throws a `RegistrationCertificateValidationError` with the `issues`, whose paths start with `header` or `payload`:

- `invalid_signature`, when a signature does not verify or the callback does not trust its signer.
- `expired` and `not_yet_valid` from the claims, with the time as context, at the name of the claim of a JWT and at the key of the claim of a CWT.
- `status_list_unavailable`, when the status list cannot be fetched, and `invalid_status_list`, when it does not verify. Either way no statement about the status can be made.
- `revoked`, with the `status` as context. ETSI TS 119 475 only defines valid and revoked (REV-6.2.6.2-04), so any status other than valid is revoked.

`verifyRegistrationCertificateStatus` checks the status on its own, with the same callbacks.

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

Checking the code, e.g. `issue.code === 'invalid_typ'`, narrows the `context` to the one of that code. `assertValidRegistrationCertificatePayload`, `parseRegistrationCertificatePayload` and `assertValidRegistrationCertificate` throw a `RegistrationCertificateValidationError` with the same `issues`. So do signing, decoding and verification: every error of this package is a `RegistrationCertificateValidationError`.

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

- The query is parsed and validated with the [`dcql`](../dcql) library. A query it rejects gets its issues, at their location in the query and with a code of `DCQL_VALIDATION_CODES`, such as `duplicate_credential_query_id`, or a schema code, such as `missing_value`. A claims query without `path` (the `namespace` and `claim_name` form of earlier OpenID4VP drafts) gives an `invalid_query` issue.
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
- **GEN-5.2.1-05**: CWT signed as a COSE_Sign1 (RFC 9052) with the `x5chain` of RFC 9360
- **GEN-5.2.2 / GEN-5.2.3**: JWT/CWT headers with `typ: "rc-wrp+jwt"` or `typ: "rc-wrp+cwt"`
- **GEN-5.2.4-03**: At least one entitlement must be specified
- **GEN-5.2.4-04**: Sub-entitlements require the base entitlement
- **GEN-5.2.4-05**: Attestation providers should specify `provides_attestations`
- **GEN-5.2.4-06**: Service providers should specify `credentials` and `purpose`
- **GEN-5.2.4-08**: `exp` at most 12 months after `iat`
- Under intermediation, `intermediary.sub` is checked against the supplied access-certificate subject
- **Clause 6.2.6**: status required (REV-6.2.6.2-03) and checked in the referenced status list, valid or revoked (REV-6.2.6.2-04)

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
- `zRegistrationCertificateJwtHeader` - JWT header validation
- `zRegistrationCertificateCwtHeader` - CWT header validation
- `zCredential` - Credential specification validation
- `zClaim` - Claim specification validation
- `zMultiLangString` - Multilingual string validation

### Types

- `RegistrationCertificatePayload` - Registration certificate payload type
- `RegistrationCertificateJwtHeader` - JWT header type
- `SignedRegistrationCertificateJwt` - Signed registration certificate with JWS string
- `SignedRegistrationCertificateCwt` - Signed registration certificate with the encoded COSE_Sign1
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
- `validateRegistrationCertificateJwtHeader(header)` - Validate JWT header
- `validateRegistrationCertificateCwtHeader(header)` - Validate CWT protected header
- `validateRegistrationCertificate(header, payload, accessCertificateSub)` - Validate complete registration certificate and access-certificate identity
- `assertValidRegistrationCertificatePayload(payload, accessCertificateSub)` - Assert or throw
- `parseRegistrationCertificatePayload(payload, accessCertificateSub)` - Validate and return the canonical payload

### Dialects

- `REGISTRATION_CERTIFICATE_DIALECTS` - Supported wire dialects
- `normalizeRegistrationCertificatePayload(value)` - Map either spelling to the published one
- `toRegistrationCertificateDialect(payload, dialect)` - Serialize a canonical payload in a dialect

### Signer

- `signRegistrationCertificateJwt(options)` - Sign a registration certificate payload to a JAdES B-B signed JWT
- `decodeRegistrationCertificateJwt(jws, accessCertificateSub)` - Decode and validate a signed registration certificate
- `parseRegistrationCertificateJwt(jws)` - Parse without validation
- `signRegistrationCertificateCwt(options)` - Sign a registration certificate payload to CWT
- `RegistrationCertificateCwt`, `RegistrationCertificateCwtPayload` - The CWT and its claims set as CBOR structures
- `decodeRegistrationCertificateCwt(cwt, accessCertificateSub)` - Decode and validate a CWT registration certificate

### Presentation requests

- `mdocRegistrationCertificateExtension(registrationCertificate)` - The `euWrprc` entry for the `requestInfo` of an `ItemsRequest`
- `decodeMdocRegistrationCertificate(requestInfo, accessCertificateSub)` - Decode the registration certificate of an mdoc request
- `openid4vpRegistrationCertificateVerifierInfo(jws, options)` - The `registration_cert` element of `verifier_info`
- `decodeOpenid4vpRegistrationCertificate(verifierInfo, accessCertificateSub)` - Decode the registration certificate of an OpenID4VP request

### Verification

- `verifyRegistrationCertificate(options)` - Verify a JWT or CWT registration certificate, including its status
- `verifyRegistrationCertificateStatus(options)` - Check the status of a registration certificate in its status list
- `VerifyRegistrationCertificateCallbacks` - The `verifyJws`, `verifyCose` and `fetch` callbacks

## Contributing

See the [Contributing Guide](https://github.com/openwallet-foundation-labs/identity-common-ts/blob/main/CONTRIBUTING.md) for details on how to contribute to this project.

## License

This project is licensed under the [Apache License Version 2.0](https://github.com/openwallet-foundation-labs/identity-common-ts/blob/main/LICENSE) (Apache-2.0).
