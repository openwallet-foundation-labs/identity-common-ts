# @owf/eudi-access-certificate

[![npm version](https://img.shields.io/npm/v/@owf/eudi-access-certificate)](https://npmjs.com/package/@owf/eudi-access-certificate)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://github.com/openwallet-foundation-labs/identity-common-ts/blob/main/LICENSE)

Parse, validate and create EUDI **wallet-relying party access certificates** as specified in
[ETSI TS 119 411-8 V1.1.1](https://www.etsi.org/deliver/etsi_ts/119400_119499/11941108/01.01.01_60/ts_11941108v010101p.pdf)
(Access Certificate Policy for EUDI Wallet Relying Parties).

This package is a profile on top of [`@owf/x509`](../x509). `@owf/x509` handles the generic X.509 work: parsing,
creation, signature verification and CRLs. This package adds what TS 119 411-8 defines: the policy identifiers, the
subject and contact requirements, and the QC statements for qualified policies. Like `@owf/x509`, it runs on servers,
in browsers and in React Native, and signing is a callback.

## Installation

```bash
npm install @owf/eudi-access-certificate @owf/x509
```

## Parsing

```typescript
import { parseAccessCertificate } from '@owf/eudi-access-certificate'

// PEM, base64 encoded DER, or DER bytes, e.g. the first entry of an x5c header
const ac = parseAccessCertificate(pem)

ac.policies           // ['QCP-l-eudiwrp']
ac.subjectType        // 'legal' | 'natural'
ac.qualified          // true for QCP-n-eudiwrp / QCP-l-eudiwrp
ac.subjectIdentifier  // { type: 'VAT', countryCode: 'DE', identifier: '123456789', ... }
ac.contact            // { uris, emails, phoneNumbers } from the SAN (GEN-6.6.1-07)

ac.certificate        // the generic @owf/x509 Certificate
ac.certificate.subject.commonName               // trade or service name (GEN-6.1.1-04)
ac.certificate.policies[0].cpsUris              // GEN-6.6.1-06
ac.certificate.subjectAlternativeNames.dnsNames // e.g. for the OpenID4VP x509_san_dns client identifier
```

If you already have a parsed certificate from `@owf/x509`, use `toAccessCertificate(certificate)`.

### Relation to registration certificates

A registration certificate (ETSI TS 119 475, see [`@owf/eudi-wrprc`](../eudi-wrprc)) is bound to the access certificate
through its `sub` claim. `getAccessCertificateSubjectIdentifier(ac)` returns the value to compare it with: the
`organizationIdentifier` for legal persons, or the `serialNumber` for natural persons.

```typescript
import { getAccessCertificateSubjectIdentifier } from '@owf/eudi-access-certificate'
import { validateWRPRC } from '@owf/eudi-wrprc'

const result = validateWRPRC(header, payload, getAccessCertificateSubjectIdentifier(ac) ?? '')
```

## Validation

`validateAccessCertificate` checks the certificate profile of TS 119 411-8 clause 6.6.1 and the profiles it
references (ETSI EN 319 412-1/-2/-3/-5):

| Code | Severity | Requirement |
|------|----------|-------------|
| `MISSING_POLICY` / `CONFLICTING_POLICIES` | error | GEN-6.6.1-03: a TS 119 411-8 policy OID (or an accepted TSP OID); natural and legal policies must not be mixed |
| `MISSING_CPS_URI` | error | GEN-6.6.1-06 |
| `MISSING_CONTACT` | error | GEN-6.6.1-07: SAN website, telephone number or email address |
| `MISSING_ORGANIZATION_IDENTIFIER` / `INVALID_ORGANIZATION_IDENTIFIER` / `INVALID_GREECE_COUNTRY_CODE` | error | GEN-6.6.1-05 (legal persons) |
| `MISSING_COMMON_NAME` / `MISSING_COUNTRY_NAME` / `MISSING_ORGANIZATION_NAME` | error | EN 319 412-2 / 412-3 |
| `MISSING_NATURAL_PERSON_NAME` | error | EN 319 412-2: givenName and/or surname, or pseudonym |
| `MISSING_SERIAL_NUMBER` / `INVALID_SERIAL_NUMBER` | warning | Natural person semantic identifier (EN 319 412-1 clause 5.1.3) |
| `MISSING_QC_COMPLIANCE` | error | GEN-6.6.1-02: qualified policies need the QcCompliance statement |
| `QC_TYPE_MISMATCH` | warning | GEN-6.6.1-02: `esign` for natural and `eseal` for legal persons |
| `CA_CERTIFICATE`, `UNSUPPORTED_VERSION`, `NOT_YET_VALID`, `EXPIRED` | error | X.509 basics |
| `MISSING_DIGITAL_SIGNATURE_KEY_USAGE` | warning | The key has to sign to authenticate the relying party |

```typescript
import { parseAndValidateAccessCertificate, validateAccessCertificate } from '@owf/eudi-access-certificate'

const { valid, errors, warnings } = validateAccessCertificate(ac, {
  now: new Date(),                     // or false to skip the validity period check
  acceptedPolicyOids: ['1.2.3.4.5'],   // TSP allocated policy OIDs (GEN-6.6.1-03)
})

// Or throw an AccessCertificateException on errors
const checked = parseAndValidateAccessCertificate(pem)
```

## Signature and revocation checks

These are generic X.509 operations. Run them with `@owf/x509` on `ac.certificate`:

```typescript
import { checkRevocation, parseCrl, verifyCertificateSignature } from '@owf/x509'

const signed = await verifyCertificateSignature(ac.certificate, providerCaPem, verifier)

// REV-6.3.9-04: access certificates are revoked when the registration is suspended or cancelled
const crl = parseCrl(await fetchCrl(ac.certificate.crlDistributionPoints[0]))
const status = await checkRevocation({ certificate: ac.certificate, crl, crlIssuerCertificate: providerCaPem, verifier })
```

Take the provider CA from the trusted list of access certificate providers (see [`@owf/eudi-lote`](../eudi-lote)).

## Creation

Certificates are created without handing over any private key:

- the **issuing CA key** stays wherever it lives (WebCrypto, KMS, HSM). The `signer` callback receives the DER encoded
  TBSCertificate and returns the signature.
- for the **wallet-relying party** only the public key is needed, as SPKI bytes or as a JWK. A JWK that contains
  private key material is rejected.

```typescript
import { createAccessCertificate } from '@owf/eudi-access-certificate'

const ac = await createAccessCertificate({
  policy: 'NCP-l-eudiwrp', // or 'QCP-l-eudiwrp', 'NCP-n-eudiwrp', 'QCP-n-eudiwrp'
  cpsUri: 'https://ca.example.com/cps',
  subject: {
    commonName: 'Example Shop',
    organizationName: 'Example Relying Party GmbH',
    organizationIdentifier: 'LEIXG-529900T8BM49AURSDO55',
    countryName: 'DE',
    organizationalUnitNames: ['Online Shop'],
  },
  contact: { uris: ['https://shop.example.com/support'], emails: ['support@shop.example.com'] },
  dnsNames: ['shop.example.com'],
  subjectPublicKey: relyingPartyPublicJwk,
  issuerCertificate: caPem,
  serialNumber: randomSerialHex, // at most 20 octets, generate it with your CSPRNG
  notBefore: new Date(),
  notAfter: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000),
  signatureAlgorithm: 'ES256',
  crlDistributionPoints: ['https://ca.example.com/crl'],
  signer: async (tbs) => new Uint8Array(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, caKey, tbs)),
  signatureEncoding: 'ieee-p1363', // default, as produced by WebCrypto; use 'der' for most KMS/HSM APIs
})

ac.certificate.pem
```

The certificate gets the policy OID with the CPS URI, the contact information in the SAN (telephone numbers as
`otherName` with `id-at-telephoneNumber`), `basicConstraints` `cA=false`, `keyUsage` `digitalSignature`, and an
authority key identifier taken from the issuer certificate. Qualified policies also get QC statements with
QcCompliance and QcType (`esign` / `eseal`), optionally QcSSCD, PDS locations and QcCClegislation. The result is
validated against the profile before it is returned.

If the key lives in a separate system, use `prepareAccessCertificate(options)` and
`assembleAccessCertificate(prepared, signature)`. `toCertificateTemplate(options)` returns the generic `@owf/x509`
template if you need to adjust it further.

## Out of scope

- Path building to a trust anchor
- Certificate transparency (OVR-6.4.5-02)
- Checking the wallet-relying party against the national register (REG-6.2.2-03), which is the provider's job at
  issuance
