# @owf/jose

[![npm version](https://img.shields.io/npm/v/@owf/jose)](https://npmjs.com/package/@owf/jose)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://github.com/openwallet-foundation-labs/identity-common-ts/blob/main/LICENSE)

JOSE (JWK, JWA and JWS) for [Identity Common TypeScript](https://github.com/openwallet-foundation-labs/identity-common-ts). Tokens are parsed and verified strictly, against zod schemas.

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

A token type is described by a schema. Compose the exported schemas into the protected header a token must have, and `parseJws` checks everything that follows from the token alone:

```typescript
import { zTyp } from '@owf/identity-common'
import { parseJws, zJwsProtectedHeader } from '@owf/jose'
import z from 'zod'

const zExampleHeader = z.object({ ...zJwsProtectedHeader.shape, typ: zTyp('example+jws') }).loose()

// `protectedHeader` is typed from the schema
const { protectedHeader, payload } = parseJws({ jws, protectedHeaderSchema: zExampleHeader })
```

`parseJws` also validates the protected header against `zJwsProtectedHeader` and returns the result as `registeredProtectedHeader`. The checks run on that result, so a profile schema cannot leave `alg` or `crit` unchecked.

The algorithms a verifier accepts and the way the signer is identified are options of `verifyJwsSignature`, as a schema cannot express them.

## Signing and verifying

The caller provides the cryptography. This package computes the bytes to sign, and the callback signs or verifies exactly those bytes.

```typescript
import { base64url } from '@owf/identity-common'
import {
  type JwsSigner,
  jwsHeaderFromSigner,
  parseJws,
  type SignJwsCallback,
  signCompactJws,
  type VerifyJwsCallback,
  verifyJwsSignature,
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

const { compact } = await signCompactJws({
  // The parameters that identify the key are only in the header when they are put there
  protectedHeader: { typ: 'example+jws', ...jwsHeaderFromSigner(signer) },
  payload: { hello: 'world' },
  signer,
  signJwsCallback: signJws,
})

// The signer is established from the header, here from its `jwk`
const { signer: verifiedSigner } = await verifyJwsSignature({
  jws: parseJws({ jws: compact }),
  verifyJwsCallback: verifyJws,
  allowedAlgorithms: ['ES256'],
})
```

The verification callback decides whether the key is trusted, for example whether a certificate chain chains to a trusted root or whether a DID is acceptable. This package only establishes which key signed.

`signCompactJws` validates the protected header before signing it. It does not add the header parameters that identify the key, because the token type decides which of them a token carries. Spread `jwsHeaderFromSigner(signer)` into the header to add them. It returns:

- for a `did` signer, its DID URL as `kid`
- for a `federation` signer, `kid` and `trust_chain`. Without a trust chain it gives `kid` alone, and a verifier then establishes a `custom` signer
- for a `jwk` or `x5c` signer, `jwk` or `x5c`, without the `kid` of the signer
- for a `custom` signer, its `kid` when it has one, as the key id is all a verifier has to find a key that is established out of band

## Certificate chains

`x5c`, in a JWS header and in a JWK, is validated when it is parsed, as RFC 7515 and RFC 7517 define it: a chain of at least one certificate, with the certificate that holds the key first. Each entry is the standard base64 (RFC 4648 section 4) of a DER encoded certificate. An entry is rejected when it has base64url characters, whitespace or line breaks, or missing or extra `=` padding. It is also rejected when it does not decode to exactly one DER SEQUENCE with a definite, minimally encoded length. The issue has the path of the entry and the code `invalid_format`, with `base64` or `der` as the format.

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
- An unencoded payload (RFC 7797, `b64: false`) is only carried in a compact serialization when it holds nothing but printable ASCII other than `.`, as RFC 7797 requires. Signing refuses anything else, and parsing rejects it. A detached payload, or one in a JSON serialization, is not limited this way.

`signCompactJws` throws a `JoseInvalidArgumentError` for a signer whose `alg` is not the `alg` of the header, and for a signing callback that does not return a non-empty base64url signature.

## Errors

The errors of this package extend `IdentityError` from `@owf/identity-common`. The class says what went wrong:

- `JoseParseError`: the token is not well formed.
- `JoseValidationError`: the token does not match the schema it was parsed with. It extends the `ValidationError` of `@owf/identity-common` and has the `issues` of the validation, e.g. `invalid_typ` for a wrong `typ`. It is also thrown for a `crit` that does not verify (`invalid_crit`, `unsupported_crit`), and for a claim that does not verify (e.g. `expired`, with `expiredAt` as context). `error.findIssue('expired')` returns the issue with that code, typed by it.
- `JoseVerificationError`: the token does not verify. Its subclasses are `JoseSignatureVerificationError`, `JoseAlgorithmNotAllowedError` and `JoseSignerError`.
- `JoseNotSupportedError`: the token uses a feature this package does not implement.
- `JoseInvalidArgumentError`: the calling code passed an option that cannot be used, or a signing callback returned an unusable result. A verification callback that reports success without a usable `signerJwk` gives a `JoseSignatureVerificationError` instead.

## Not supported

- An unsecured JWS (`alg: none`), and a JWS without a protected header.
- Signing a JWS in a JSON serialization. `parseJws` and `verifyJwsSignature` read the flattened and general JSON serializations, but `signCompactJws` produces the compact serialization only.
- An unencoded payload (`b64: false`) that is not valid UTF-8.

## Platform support

This library works in:

- Node.js (>=20)
- Browsers with ES2020 support
- React Native

## Contributing

See the [Contributing Guide](https://github.com/openwallet-foundation-labs/identity-common-ts/blob/main/CONTRIBUTING.md) for details on how to contribute to this project.

## License

This project is licensed under the [Apache License Version 2.0](https://github.com/openwallet-foundation-labs/identity-common-ts/blob/main/LICENSE) (Apache-2.0).
