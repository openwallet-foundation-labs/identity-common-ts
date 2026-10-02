# @owf/x509

[![npm version](https://img.shields.io/npm/v/@owf/x509)](https://npmjs.com/package/@owf/x509)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://github.com/openwallet-foundation-labs/identity-common-ts/blob/main/LICENSE)

Environment agnostic X.509 certificates and certificate revocation lists (RFC 5280): parse, create, verify and check
revocation.

The package is pure TypeScript on top of [`@peculiar/asn1-x509`](https://www.npmjs.com/package/@peculiar/asn1-x509) and
[`asn1js`](https://www.npmjs.com/package/asn1js). It uses neither Node.js built-ins, global crypto nor
`reflect-metadata`, so it runs on servers, in browsers and in React Native. Signing and signature verification are
callbacks, so private keys never enter the package and can stay in WebCrypto, a KMS or an HSM.

Profiles such as [`@owf/eudi-access-certificate`](../eudi-access-certificate) (ETSI TS 119 411-8) are built on top of it.

## Installation

```bash
npm install @owf/x509
```

## Certificates

### Parsing

```typescript
import { parseCertificate } from '@owf/x509'

const cert = parseCertificate(pem) // PEM, base64 DER or DER bytes

cert.subject.commonName
cert.subject.rfc4514          // 'CN=Example,O=Example GmbH,C=DE'
cert.serialNumber             // lowercase hex
cert.notBefore / cert.notAfter
cert.publicKey.jwk            // EC (P-256/384/521) and RSA keys as JWK
cert.policies                 // [{ oid, cpsUris, userNotices }]
cert.subjectAlternativeNames  // { dnsNames, uris, emails, ipAddresses, directoryNames, otherNames }
cert.keyUsage, cert.extendedKeyUsage, cert.basicConstraints
cert.subjectKeyIdentifier, cert.authorityKeyIdentifier
cert.crlDistributionPoints, cert.ocspUrls, cert.caIssuersUrls
cert.qcStatements             // RFC 3739 / ETSI EN 319 412-5
cert.extensions               // every extension as { oid, critical, value }
```

### Verifying a signature

```typescript
import { verifyCertificateSignature } from '@owf/x509'

const ok = await verifyCertificateSignature(cert, issuerPem, async ({ data, signatureP1363, publicKey }) => {
  const key = await crypto.subtle.importKey('jwk', publicKey.jwk!, { name: 'ECDSA', namedCurve: 'P-256' }, false, [
    'verify',
  ])
  return crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, key, signatureP1363, data)
})
```

The verifier receives the signed bytes, the signature both as encoded (DER for ECDSA) and as IEEE P1363 (`r || s`, what
WebCrypto expects), and the issuer public key as SPKI and JWK. Issuer name and key identifiers have to match as well.
This checks a single link. Path building to a trust anchor is up to the caller.

### Creating

```typescript
import { createCertificate, stringOtherName, ATTRIBUTE_TYPES } from '@owf/x509'
import { digest } from '@owf/crypto'

const cert = await createCertificate({
  subject: [
    ['countryName', 'DE'],
    ['organizationName', 'Example GmbH'],
    ['commonName', 'Example Service'],
  ],
  subjectPublicKey: publicJwk, // or SPKI bytes; private JWKs are rejected
  issuerCertificate: caPem,    // omit for a self-signed certificate
  serialNumber: randomSerialHex,
  notBefore: new Date(),
  notAfter: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000),
  signatureAlgorithm: 'ES256', // ES256, ES384, ES512, RS256, RS384, RS512
  certificatePolicies: [{ oid: '1.2.3.4', cpsUris: ['https://ca.example.com/cps'] }],
  subjectAlternativeNames: {
    dnsNames: ['service.example.com'],
    otherNames: [stringOtherName(ATTRIBUTE_TYPES.telephoneNumber, '+4930123456')],
  },
  crlDistributionPoints: ['https://ca.example.com/crl'],
  hasher: digest, // optional: subject key identifier (RFC 7093 method 1)
  signer: async (tbs) => new Uint8Array(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, caKey, tbs)),
  signatureEncoding: 'ieee-p1363', // default (WebCrypto); use 'der' for most KMS / HSM APIs
})
```

Defaults: `basicConstraints` `cA=false` and `keyUsage` `digitalSignature` for end-entity certificates, and
`keyCertSign, crlSign` for CAs. Both are marked critical. The authority key identifier is taken from the issuer
certificate. Custom extensions can be appended through `extensions`.

For keys in a separate system, split creation into two steps:

```typescript
const prepared = await prepareCertificate(template)
const signature = await remoteSigningService.sign(prepared.tbs)
const cert = assembleCertificate(prepared, signature, 'der')
```

## CRLs

### Parsing and checking revocation

```typescript
import { checkRevocation, parseCrl } from '@owf/x509'

// Fetch the CRL yourself, e.g. from cert.crlDistributionPoints
const crl = parseCrl(new Uint8Array(await (await fetch(cert.crlDistributionPoints[0])).arrayBuffer()))

const status = await checkRevocation({ certificate: cert, crl, crlIssuerCertificate: issuerPem, verifier })
// { status: 'good' }
// { status: 'revoked', revocationDate, reason?, invalidityDate? }
// { status: 'unknown', reason, message }
```

`checkRevocation` verifies the CRL signature first. The CRL issuer's key usage has to allow `cRLSign` if it is present.
Then it returns `unknown` instead of guessing in these cases:

| Reason | When |
|--------|------|
| `invalid_signature` | The CRL signature does not verify, or the CRL is not issued by the given certificate |
| `issuer_mismatch` | The CRL is not issued by the certificate issuer, or is signed by a different key |
| `crl_not_yet_valid` / `crl_expired` | `now` is before `thisUpdate` or after `nextUpdate` |
| `out_of_scope` | The issuing distribution point excludes the certificate (user/CA/attribute only, different distribution point, only some reasons) |
| `delta_crl` | The CRL is a delta CRL, which needs its base CRL |
| `unsupported_critical_extension` | The CRL or the matching entry has a critical extension this package does not understand |

Indirect CRLs (with `certificateIssuer` entries) are supported. Entries with reason `removeFromCRL` count as not
revoked. `getRevocationStatus(cert, crl)` performs the same lookup without checking the signature, for CRLs you have
already verified.

`parseCrl` limits the number of entries to 100 000 by default, to protect against resource exhaustion by untrusted
input. Raise it with `parseCrl(input, { maxEntries })`.

### Creating

```typescript
import { createCrl } from '@owf/x509'

const crl = await createCrl({
  issuerCertificate: caPem,
  thisUpdate: new Date(),
  nextUpdate: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
  crlNumber: 42n,
  signatureAlgorithm: 'ES256',
  revokedCertificates: [{ serialNumber: '0badc0de', revocationDate: new Date(), reason: 'keyCompromise' }],
  issuingDistributionPoint: { distributionPointUris: ['https://ca.example.com/crl'], onlyContainsUserCerts: true },
  signer,
})

crl.pem // -----BEGIN X509 CRL-----
```

`prepareCrl` / `assembleCrl` provide the same two-step flow as for certificates.

## Out of scope

- Certification path building and validation (RFC 5280 clause 6)
- OCSP
- Certificate signing requests
