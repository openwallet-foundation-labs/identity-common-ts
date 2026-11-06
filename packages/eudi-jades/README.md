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
- Built on [`@owf/jose`](../jose), which parses, signs and verifies the JWS through callbacks

## Create a B-B Signature

`signJades` validates the protected header against clause 5 and signs it with `signCompactJws`, `signFlattenedJws` or `signGeneralJws` of `@owf/jose`. The signer and the callbacks are those of `@owf/jose`. New JAdES signatures created on or after 2025-07-15 use the integer `iat` claimed signing time, which defaults to now. The historical `sigT` parameter remains accepted when verifying older signatures but is rejected when signing.

```typescript
import { parseCertificateChain } from '@owf/crypto'
import { signJades } from '@owf/eudi-jades'

const { jws } = await signJades({
  payload: { hello: 'world' },
  // `x5c` signer: the certificate chain goes into the protected header
  signer: { method: 'x5c', alg: 'ES256', x5c: parseCertificateChain(pemCertificate) },
  signJwsCallback,
})

const { jws: general } = await signJades({ serialization: 'general', payload, signer, signJwsCallback })
```

A signature needs a reference to the signing certificate (clause 5.1.7 and 5.1.8). An `x5c` signer gives it, or set `x5t#S256`, `x5t#o` or `sigX5ts` in `protectedHeader`.

## Verify

```typescript
import { verifyJades, verifyJadesJwt } from '@owf/eudi-jades'

const { protectedHeader, payload, signer } = await verifyJades({ jws, verifyJwsCallback })

// A JWT signed as a JAdES signature, with its claims verified by `verifyJwt` of @owf/jose
const { payload: claims } = await verifyJadesJwt({ jwt, verifyJwsCallback, expectedIssuer: 'https://issuer.example' })
```

The callback verifies the signature and decides whether the signing certificate is trusted. `verify*` first decode the signature with `decodeJades`, which checks the headers against clause 5 and the B-B profile, or the one given as `profile`. `decodeJades` does the same without verifying the signature.

## Errors and validation issues

A signature or a header that does not meet ETSI TS 119 182-1 throws a `JadesValidationError` with the `issues` of the validation, from `signJades` as well as from `decodeJades` and `verify*`. Each issue has a `code`, a `path` and a `message`. The codes are those of `SCHEMA_VALIDATION_CODES` of `@owf/identity-common`, such as `missing_value` or `not_allowed`, and of `JADES_VALIDATION_CODES` for the JAdES checks they do not cover:

- `missing_certificate_reference`, when none of `x5t#S256`, `x5c`, `x5t#o` and `sigX5ts` is present.
- `invalid_timestamp`, for a baseline time-stamp that is not a single RFC 3161 token in `val`.
- `missing_validation_data`, when B-LT or B-LTA validation data is not evidenced.

A `crit` that repeats an entry, names an absent or registered parameter, or lacks `sigD` or `b64` gives the `invalid_crit` of `VALIDATION_CODES`, the code `@owf/jose` uses for `crit` too.

A path starts with `protected`, `header` or `payload`, the members of a JSON serialization:

```typescript
try {
  await verifyJades({ jws, verifyJwsCallback })
} catch (error) {
  if (error instanceof JadesValidationError) {
    const reference = error.findIssue('missing_certificate_reference')
  }
}
```

The JWS itself is parsed, signed and verified by `@owf/jose`, whose errors are thrown as they are: `JoseValidationError`, also with `issues`, for a JWS that does not validate, and `JoseSignatureVerificationError` for a signature that does not verify.

## Unsigned Properties and B-T

The JWS Unprotected Header of a JAdES signature may contain only `etsiU`. Because compact JWS has no unprotected header, a signature containing `etsiU` must use a JSON serialization.

```typescript
const { jws } = await signJades({
  serialization: 'general',
  unprotectedHeader: {
    etsiU: [{ sigTst: { tstTokens: [{ val: base64EncodedRfc3161Token }] } }],
  },
  payload,
  signer,
  signJwsCallback,
})
```

All clear `etsiU` elements are single-property objects. They cannot be mixed with base64url-encoded elements.
Time-stamp containers in clear unsigned values require `canonAlg`, except `sigTst`, which prohibits it.

## Detached Payloads

```typescript
import { DETACHED_MECHANISM_IDS, signJades, verifyJades } from '@owf/eudi-jades'

const payload = 'the already constructed detached JWS Payload'
const { jws } = await signJades({
  serialization: 'general',
  payload,
  sigD: { mId: DETACHED_MECHANISM_IDS.objectByUri, pars: ['https://example.test/document'] },
  signer,
  signJwsCallback,
})

// The payload is omitted from `jws`
await verifyJades({ jws, verifyJwsCallback, detachedPayload: payload })
```

`sigD` is marked critical. For `ObjectIdByURIHash`, `hashM` and `hashV` are required and the JWS Payload contributes an empty stream to the signature computation, so no payload is given when signing or verifying. For `HttpHeaders`, `b64` is set to `false`, and `hashM`, `hashV` and `ctys` are prohibited.

## Baseline Profiles

```typescript
import { decodeJades, JadesProfile, validateProfile } from '@owf/eudi-jades'

// Throws a JadesValidationError when the signature does not meet B-T
const decoded = decodeJades({ jws, profile: JadesProfile.B_T })

// Or the issues without throwing: { valid, issues }
const result = validateProfile(decoded.protectedHeader, JadesProfile.B_T, decoded.unprotectedHeader)
```

`validateProfile` checks component structure, placement, cardinality, prohibited reference components at B-LT/B-LTA,
and evidence that required validation-data services are present. It does not validate X.509 paths, revocation status,
RFC 3161 tokens, signature-policy semantics, or the completeness/freshness of validation material. Those checks require
a trust policy and PKI/time-stamp validation engine supplied by the application.

When validation material is embedded inside an opaque token, pass the corresponding evidence explicitly:

```typescript
validateProfile(header, JadesProfile.B_LT, unprotectedHeader, {
  signatureValidationDataAvailable: true,
  timestampValidationDataAvailable: true,
})
```

## License

Apache-2.0
