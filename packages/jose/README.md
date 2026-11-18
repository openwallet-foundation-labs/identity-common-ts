# @owf/jose

[![npm version](https://img.shields.io/npm/v/@owf/jose)](https://npmjs.com/package/@owf/jose)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://github.com/openwallet-foundation-labs/identity-common-ts/blob/main/LICENSE)

JOSE (JWK, JWA, JWS, JWT and JWE) for [Identity Common TypeScript](https://github.com/openwallet-foundation-labs/identity-common-ts). Tokens are parsed and verified strictly, against zod schemas.

## Installation

```bash
# Using npm
npm install @owf/jose

# Using pnpm
pnpm add @owf/jose

# Using yarn
yarn add @owf/jose
```

## Design

Every base64url, UTF-8 and JSON decode goes through `@owf/identity-common`. It accepts only the base64url alphabet without padding, decodes UTF-8 with `fatal: true`, and throws the same opaque error for every failure. A header encoded with the standard base64 alphabet, or a payload with invalid UTF-8, is rejected.

A token type is described by a schema. Compose the exported schemas into the header and claims a token must have, and `decodeJwt` checks everything that follows from the token alone:

```typescript
import { zTyp } from '@owf/identity-common'
import { decodeJwt, zJwtHeader, zJwtPayload } from '@owf/jose'
import z from 'zod'

const zKbJwtHeader = z.object({ ...zJwtHeader.shape, typ: zTyp('kb+jwt') }).loose()
const zKbJwtPayload = z
  .object({ ...zJwtPayload.shape, iat: z.number(), aud: z.string(), nonce: z.string(), sd_hash: z.string().min(1) })
  .loose()

// `header` and `payload` are typed from the schemas
const { header, payload } = decodeJwt({
  jwt,
  headerSchema: zKeyBindingJwtHeader,
  payloadSchema: zKeyBindingJwtPayload,
})
```

`decodeJwt` also validates the header against `zJwtHeader` and the payload against `zJwtPayload`. The checks run on those results, so a profile schema cannot leave `alg`, `crit` or `exp` unchecked.

The current time, the audience of the verifier and the nonce it issued are options of `verifyJwt`, as a schema cannot express them.

## Signing and verifying

The caller provides the cryptography. This package computes the bytes to sign, and the callback signs or verifies exactly those bytes.

```typescript
import { base64url, dateToSeconds } from '@owf/identity-common'
import {
  type JwsSigner,
  jwsHeaderFromSigner,
  type SignJwsCallback,
  signJwt,
  type VerifyJwsCallback,
  verifyJwt,
} from '@owf/jose'

// `kms`, `resolveKey` and `resolveTrustedKey` stand in for your own key management
const signJws: SignJwsCallback = async (signer, { signingInputBytes }) => {
  const { keyId, publicJwk } = await resolveKey(signer)
  const signature = await kms.sign({ keyId, algorithm: signer.alg, data: signingInputBytes })

  return { signature: base64url.encode(signature), signerJwk: publicJwk }
}

const verifyJws: VerifyJwsCallback = async (signer, { signingInputBytes, signature }) => {
  // Throws when the key the header names is not one this verifier trusts
  const publicJwk = await resolveTrustedKey(signer)
  const verified = await kms.verify({
    publicJwk,
    algorithm: signer.alg,
    data: signingInputBytes,
    signature: base64url.decode(signature),
  })

  return verified ? { verified: true, signerJwk: publicJwk } : { verified: false }
}

const signer: JwsSigner = { method: 'jwk', alg: 'ES256', publicJwk }

const { jwt } = await signJwt({
  // The parameters that identify the key are only in the header when they are put there
  header: { typ: 'example+jwt', ...jwsHeaderFromSigner(signer) },
  payload: { iss: 'https://issuer.example', aud: 'https://verifier.example', iat: dateToSeconds(new Date()) },
  signer,
  signJwsCallback: signJws,
})

// The signer is established from the header, here from its `jwk`
const { payload, signer: verifiedSigner } = await verifyJwt({
  jwt,
  verifyJwsCallback: verifyJws,
  allowedAlgorithms: ['ES256'],
  expectedIssuer: 'https://issuer.example',
  expectedAudience: 'https://verifier.example',
  requiredClaims: ['iat'],
})
```

The verification callback decides whether the key is trusted, for example whether a certificate chain chains to a trusted root or whether a DID is acceptable. This package only establishes which key signed.

`signJwt` validates the header and the claims set before signing them. It does not add the header parameters that identify the key, because the token type decides which of them a token carries. Spread `jwsHeaderFromSigner(signer)` into the header to add them. It returns:

- for a `did` signer, its DID URL as `kid`
- for a `federation` signer, `kid` and `trust_chain`. Without a trust chain it gives `kid` alone, and a verifier then establishes a `custom` signer
- for a `jwk` or `x5c` signer, `jwk` or `x5c`, without the `kid` of the signer
- for a `custom` signer, its `kid` when it has one, as the key id is all a verifier has to find a key that is established out of band

## JSON serializations

`signFlattenedJws` and `signGeneralJws` sign the JSON serializations of RFC 7515 section 7.2. `parseJws` and `verifyJwsSignature` parse and verify them, as they do a compact serialization. A general JSON serialization is verified one signature at a time, chosen with `signatureIndex`. A JSON serialization can carry an unprotected header, which is not covered by the signature. Its parameters must not also be in the protected header, and it cannot hold `crit`. A general JSON serialization has one payload and a signature for each entry of `signatures`, and these have to agree on `b64`, as they share the payload. An unencoded payload is not limited to printable ASCII here, as it is in a compact serialization.

```typescript
import { parseJws, signGeneralJws, verifyJwsSignature } from '@owf/jose'

const { jws } = await signGeneralJws({
  payload: { iss: 'https://issuer.example' },
  signJwsCallback: signJws,
  signatures: [
    { protectedHeader: { alg: 'ES256' }, unprotectedHeader: { kid: 'key-1' }, signer: firstSigner },
    { protectedHeader: { alg: 'ES256' }, unprotectedHeader: { kid: 'key-2' }, signer: secondSigner },
  ],
})

// Verify the second signature
await verifyJwsSignature({ jws: parseJws({ jws, signatureIndex: 1 }), verifyJwsCallback: verifyJws })
```

## Certificate chains

`x5c`, in a JWS header, a JWE header and a JWK, is validated when it is parsed, as RFC 7515 and RFC 7517 define it: a chain of at least one certificate, with the certificate that holds the key first. Each entry is the standard base64 (RFC 4648 section 4) of a DER encoded certificate. An entry is rejected when it has base64url characters, whitespace or line breaks, or missing or extra `=` padding. It is also rejected when it does not decode to exactly one DER SEQUENCE with a definite, minimally encoded length. The issue has the path of the entry and the code `invalid_format`, with `base64` or `der` as the format.

The certificates themselves are not parsed. The verification callback gets the `x5c` signer and decides whether the entries are valid X.509 certificates, whether the chain is in order and chains to a trusted root, and whether the first certificate holds the key that signed. A profile that validates a certificate chain in its own schema can use `zX5c` and `zX5cCertificate`.

## What is checked

Besides validating the structures, verification applies these rules:

- `alg` is never `none`, in any casing, and a JWS without a signature is rejected. A caller can restrict verification to the algorithms an issuer is known to use. Symmetric algorithms are rejected unless explicitly allowed, since anyone who can verify such a token can also issue one. A registered algorithm in a different casing (`hs256`) is rejected too.
- The key a signature was verified with has to be usable with the algorithm of the token: `HS256` over an RSA public key is rejected, and so is a key that declares a different `alg`, `use` or `key_ops`. `EdDSA` and its fully specified forms `Ed25519` and `Ed448` (RFC 9864) count as the same `alg`, as long as the key is on the curve they require.
- When the signer is established for a token that carries an `iss`, a DID in `kid` has to be exactly the DID in `iss`, unless `allowDidKidIssuerMismatch` is set. A prefix match is not enough. Without an `iss`, the verification callback decides whether the DID is trusted.
- A `jwk` header parameter can never carry private key material, and an `x5c` is a chain of base64 encoded DER certificates, see [Certificate chains](#certificate-chains).
- `crit` is processed. A JWS is rejected when it marks a header parameter critical that the caller does not understand, or when `crit` is in the unprotected header, empty, or names a registered parameter. The error has an issue for each of these.
- Security relevant header parameters are read from the protected header only, and a parameter present in both the protected and the unprotected header is rejected.
- A header that identifies the signer in more than one way is rejected. No precedence is applied.
- `extractJwkFromJwkSet` selects a key from a JWK Set by its `kid` and `use`. The selection is rejected when no key in the set has the `kid`, or when several keys that differ have it. Without a `kid`, it is rejected when the set holds more than one key for the use. The same JWK listed twice counts as one key.
- An unencoded payload (RFC 7797, `b64: false`) is opt-in: `parseJws` rejects a JWS with `b64` in `crit` unless `understoodCriticalParameters` includes `'b64'`. In a compact serialization, such a payload can only hold printable ASCII other than `.`, as RFC 7797 requires. Signing refuses anything else, and parsing rejects it. A detached payload, or one in a JSON serialization, is not limited this way.
- A `cnf` claim names its key in one way only: with one of `jwk`, `jwe`, `jku` (RFC 7800) and `jkt` (RFC 9449). A `kid`, for example a DID URL, is allowed on its own, with `jku` to select the key from the set, or with `jkt`, but not next to a `jwk` or `jwe`.
- The signature is verified before the claims, since the claims of a token mean nothing until its signer is established.
- The claims are verified against `now` (the current time unless it is given), with a clock skew of 30 seconds for `exp`, `nbf` and `iat` unless `skewSeconds` says otherwise. Shifted by that skew, a token is rejected from its `exp` on, at `exp` itself too, and while its `nbf` or `iat` is in the future. An `expected*` option rejects a token that does not carry the claim at all.
- The time claims are compared as numbers of seconds, so a NumericDate outside the range of a JavaScript `Date` is still ordered: an `exp` of `9999999999999` does not expire, and an `exp` of `-1e13` has expired. A time claim that is not a finite number gives an `invalid_type` issue.

Options that a check cannot be made with are rejected rather than letting the check pass. A `now` that is not a valid date, or a `skewSeconds` or `maxAgeSeconds` that is not a finite number of at least 0, throws a `JoseInvalidArgumentError`: with a skew of `NaN`, every comparison against the current time would accept the token. `signCompactJws` and `signJwt` throw the same error for a signer whose `alg` is not the `alg` of the header, for an unencoded payload that a compact serialization cannot carry, and for a signing callback that does not return a non-empty base64url signature. `verifyJwsSignature` throws a `JoseAlgorithmNotAllowedError` when the `signer` it is given has another `alg` than the JWS.

## Errors

The errors of this package extend `IdentityError` from `@owf/identity-common`. The class says what went wrong:

- `JoseParseError`: the token is not well formed.
- `JoseValidationError`: the token does not match the schema it was parsed with. It extends the `ValidationError` of `@owf/identity-common` and has the `issues` of the validation, e.g. `invalid_typ` for a wrong `typ`. It is also thrown for a `crit` that does not verify (`invalid_crit`, `unsupported_crit`), and for a claim that does not verify (e.g. `expired`, with `expiredAt` as context). `error.findIssue('expired')` returns the issue with that code, typed by it.
- `JoseVerificationError`: the token does not verify. Its subclasses are `JoseSignatureVerificationError`, `JoseAlgorithmNotAllowedError` and `JoseSignerError`.
- `JoseNotSupportedError`: the token uses a feature this package does not implement.
- `JoseInvalidArgumentError`: the calling code passed an option that cannot be used, or a signing callback returned an unusable result. A verification callback that reports success without a usable `signerJwk` gives a `JoseSignatureVerificationError` instead.

## Not supported

- An unsecured JWS (`alg: none`), and a JWS without a protected header.
- JWE encryption and decryption. The package provides the JWE structures (`zCompactJwe`, `zJweHeader`, and `decodeJwtHeader` to read the header of a compact JWE) and the callback types (`EncryptJweCallback`, `DecryptJweCallback`), and leaves the cryptography to the caller.
- Nested JWTs. `decodeJwt` expects the claims set as the payload: decrypt an outer JWE, or read an outer JWS with `parseJws`, and decode the inner JWT from its payload.
- An unencoded payload (`b64: false`) in a JWT, and an unencoded payload that is not valid UTF-8.

## Platform support

This library works in:

- Node.js (>=20)
- Browsers with ES2020 support
- React Native

## Contributing

See the [Contributing Guide](https://github.com/openwallet-foundation-labs/identity-common-ts/blob/main/CONTRIBUTING.md) for details on how to contribute to this project.

## License

This project is licensed under the [Apache License Version 2.0](https://github.com/openwallet-foundation-labs/identity-common-ts/blob/main/LICENSE) (Apache-2.0).
