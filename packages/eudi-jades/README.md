# @owf/eudi-jades

[![npm version](https://img.shields.io/npm/v/@owf/eudi-jades)](https://npmjs.com/package/@owf/eudi-jades)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://github.com/openwallet-foundation-labs/identity-common-ts/blob/main/LICENSE)

TypeScript building blocks for JSON Advanced Electronic Signatures (JAdES), aligned with
[ETSI TS 119 182-1 V1.2.1](https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.02.01_60/ts_11918201v010201p.pdf).

## Features

- Compact, General JSON, and Flattened JSON JWS serialization
- Attached and detached payloads, including the three `sigD` mechanisms from clause 5.2.8
- Runtime schemas for the signed and unsigned JAdES components in the normative ETSI JSON Schema
- Structural checks for the B-B, B-T, B-LT, and B-LTA baseline levels
- Caller-provided signing and verification functions

## Installation

```bash
pnpm add @owf/eudi-jades
```

## Create a B-B Signature

New JAdES signatures created on or after 2025-07-15 use the integer `iat` claimed signing time. The historical
`sigT` parameter remains accepted when parsing older signatures but is rejected by the current signature builder.

```typescript
import { ES256, parseCertificateChain } from '@owf/crypto'
import { Token } from '@owf/eudi-jades'

const token = new Token({ hello: 'world' })
  .setProtectedHeader({ alg: 'ES256' })
  .setX5c(parseCertificateChain(pemCertificate))
  .setSigningTime()

await token.sign(await ES256.getSigner(privateKey))

const compact = token.toString()
const general = token.toJSON()
const flattened = token.toFlattenedJSON()
```

The signer receives the exact JWS Signing Input and returns an unpadded base64url signature.

## Verify

```typescript
import { ES256 } from '@owf/crypto'
import { verifyCompact } from '@owf/eudi-jades'

const verifier = await ES256.getVerifier(publicKey)
const result = await verifyCompact(compact, verifier)

console.log(result.valid)
console.log(result.header)
console.log(result.payload)
console.log(result.rawPayload)
```

`verify` accepts compact strings, JSON serialization objects, and stringified JSON serializations. `decode` applies
the same JAdES structural checks without performing cryptographic verification.

## Unsigned Properties and B-T

The JWS Unprotected Header of a JAdES signature may contain only `etsiU`. Because compact JWS has no unprotected
header, a token containing `etsiU` must use a JSON serialization.

```typescript
token.setUnprotectedHeader({
  etsiU: [
    {
      sigTst: {
        tstTokens: [{ val: base64EncodedRfc3161Token }],
      },
    },
  ],
})

const general = token.toJSON()
```

All clear `etsiU` elements are single-property objects. They cannot be mixed with base64url-encoded elements.
Time-stamp containers in clear unsigned values require `canonAlg`, except `sigTst`, which prohibits it.

## Detached Payloads

```typescript
import { DETACHED_MECHANISM_IDS, Token, verifyGeneral } from '@owf/eudi-jades'

const payload = 'the already constructed detached JWS Payload'
const token = new Token(payload)
  .setProtectedHeader({ alg: 'ES256', x5c: certificates })
  .setSigningTime()
  .setDetached({
    mId: DETACHED_MECHANISM_IDS.objectByUri,
    pars: ['https://example.test/document'],
  })

await token.sign(signer)
const detachedJws = token.toJSON() // payload is omitted

const result = await verifyGeneral(detachedJws, verifier, 0, { detachedPayload: payload })
```

For `ObjectIdByURIHash`, `hashM` and `hashV` are required and the JWS Payload contributes an empty stream to the
signature computation. For `HttpHeaders`, `b64` is set to `false`; `hashM`, `hashV`, and `ctys` are prohibited.

## Baseline Profiles

```typescript
import { decode, JAdESProfile, validateProfile } from '@owf/eudi-jades'

const decoded = decode(jws)
const result = validateProfile(decoded.header, JAdESProfile.B_T, decoded.unprotectedHeader)
```

`validateProfile` checks component structure, placement, cardinality, prohibited reference components at B-LT/B-LTA,
and evidence that required validation-data services are present. It does not validate X.509 paths, revocation status,
RFC 3161 tokens, signature-policy semantics, or the completeness/freshness of validation material. Those checks require
a trust policy and PKI/time-stamp validation engine supplied by the application.

When validation material is embedded inside an opaque token, pass the corresponding evidence explicitly:

```typescript
validateProfile(header, JAdESProfile.B_LT, unprotectedHeader, {
  signatureValidationDataAvailable: true,
  timestampValidationDataAvailable: true,
})
```

## License

Apache-2.0
