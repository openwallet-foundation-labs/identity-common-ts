# @owf/jose

[![npm version](https://img.shields.io/npm/v/@owf/jose)](https://npmjs.com/package/@owf/jose)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://github.com/openwallet-foundation-labs/identity-common-ts/blob/main/LICENSE)

JOSE (JWK, JWA and JWS) for [Identity Common TypeScript](https://github.com/openwallet-foundation-labs/identity-common-ts), with strict, schema based parsing and verification.

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

**Encoding is handled in one place.** Every base64url, UTF-8 and JSON decode goes through `@owf/identity-common`: only the base64url alphabet, no padding, `fatal: true` UTF-8 decoding, and the same opaque error for every failure. A token whose header is encoded with the standard base64 alphabet, or whose payload contains invalid UTF-8, is rejected rather than decoded into something that looks close enough.

**A token type is a schema, not a class.** Compose the exported schemas to describe what the protected header of a token must look like, and everything that follows from the token alone is checked when it is parsed:

```typescript
import { parseJws, zJoseType, zJwsProtectedHeader } from '@owf/jose'
import z from 'zod'

const zExampleHeader = z.object({ ...zJwsProtectedHeader.shape, typ: zJoseType('example+jws') }).loose()

// `protectedHeader` is typed from the schema
const { protectedHeader, payload } = parseJws({ jws, protectedHeaderSchema: zExampleHeader })
```

The protected header is always validated against `zJwsProtectedHeader` as well, and that result is returned as `registeredProtectedHeader`. Every check is made on it, so a schema that describes a profile's own header parameters can never leave `alg` or `crit` unchecked, whatever it makes of the header.

What a schema cannot express — the algorithms a verifier accepts, the way the signer is identified — is passed to `verifyJwsSignature` instead.

## Signing and verifying

Cryptography is provided by the caller: this package computes what is signed, and the callback signs or verifies those exact bytes.

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

The verification callback is where the caller decides whether a key is trusted: whether a certificate chain chains to a trusted root, whether a DID is acceptable. This package establishes which key signed, never whether that key should be believed.

`signCompactJws` validates the protected header before it signs it, but does not add the header parameters that identify the key: which of them a token carries is decided by the token type. Spread `jwsHeaderFromSigner(signer)` into the header to add them. It gives:

- for a `did` signer, its DID URL as `kid`
- for a `federation` signer, `kid` and `trust_chain`. Without a trust chain it gives `kid` alone, and a verifier then establishes a `custom` signer
- for a `jwk` or `x5c` signer, `jwk` or `x5c`, without the `kid` of the signer
- for a `custom` signer, its `kid` when it has one: a key id is all a verifier has to find the key of a signer that is established out of band

## Certificate chains

`x5c`, in a JWS header and in a JWK, is validated when it is parsed, as RFC 7515 and RFC 7517 define it: a chain of at least one certificate, with the certificate that holds the key first. Each entry is the standard base64 (RFC 4648 section 4, not base64url) of a DER encoded certificate. An entry is rejected when it has base64url characters, whitespace or line breaks, missing or extra `=` padding, or bits set after its last byte. It is also rejected when it does not decode to exactly one DER SEQUENCE with a definite, minimally encoded length. The error names the entry, and says whether its base64 or its DER is wrong.

Only the encoding is checked: the certificates are not parsed. The verification callback is given the `x5c` signer, and decides whether the entries are valid X.509 certificates, whether the chain is in order and chains to a trusted root, and whether the first certificate holds the key that signed. `zX5c` and `zX5cCertificate` are exported for a profile that validates a certificate chain in a schema of its own.

## What is checked

Beyond validating the structures, verification applies the rules that a JOSE implementation has to apply for a signature to mean anything:

- `alg` is never `none`, in any casing, and a JWS without a signature is rejected. A caller can restrict verification to the algorithms an issuer is known to use. Symmetric algorithms are rejected unless explicitly allowed, since with one, everybody who can verify a token can also issue one. A registered algorithm in a different casing (`hs256`) is rejected too.
- The key a signature was verified with has to be usable with the algorithm of the token: `HS256` over an RSA public key is rejected, and so is a key that declares a different `alg`, `use` or `key_ops`. `EdDSA` and its fully-specified forms `Ed25519` and `Ed448` (RFC 9864) are not a different `alg`, as long as the key is on the curve they require.
- When the signer is established for a token that carries an `iss`, a DID in `kid` has to be the DID in `iss`, not merely start with it, unless `allowDidKidIssuerMismatch` is set. Without an `iss` there is nothing to bind it to, and whether the DID is trusted is left to the verification callback.
- A `jwk` header parameter can never carry private key material, and an `x5c` is a chain of base64 encoded DER certificates, see [Certificate chains](#certificate-chains).
- `crit` is processed: a critical header parameter that is not understood is rejected, as is a `crit` that is in the unprotected header, empty, or naming a registered parameter.
- Security relevant header parameters are read from the protected header only, and a parameter present in both the protected and the unprotected header is rejected.
- A header that identifies the signer in more than one way is rejected rather than resolved by precedence.
- A key is selected from a JWK Set (`extractJwkFromJwkSet`) by its `kid` and `use`, and never guessed. The selection is rejected when no key in the set has the `kid`, or when several keys that differ have it. Without a `kid`, it is rejected when the set holds more than one key for the use. The same JWK listed twice counts as one key.
- An unencoded payload (RFC 7797, `b64: false`) is only carried in a compact serialization when it holds nothing but printable ASCII other than `.`, as RFC 7797 requires. Anything else is refused when signing and rejected when parsing. A detached payload, or one in a JSON serialization, is not limited this way.

`signCompactJws` throws a `JoseInvalidArgumentError` for a signer whose `alg` is not the `alg` of the header, and for a signing callback that does not return a non-empty base64url signature.

## Errors

The errors this package raises extend `JoseError`, which extends `IdentityError` from `@owf/identity-common`, and their classes say what went wrong:

- `JoseParseError`: the token is not well-formed. Its subclass `JoseValidationError`: the token does not match the schema it was parsed with.
- `JoseVerificationError`: the token does not verify. Its subclasses are `JoseSignatureVerificationError`, `JoseClaimVerificationError` (with `claim` and `reason`), `JoseAlgorithmNotAllowedError`, `JoseCriticalHeaderError` and `JoseSignerError`.
- `JoseNotSupportedError`: the token uses a feature this package does not implement.
- `JoseInvalidArgumentError`: the calling code passed an option, or a signing callback returned a result, that cannot be used. A verification callback that reports success without a usable `signerJwk` fails verification instead, with a `JoseSignatureVerificationError`.

## Not supported

- An unsecured JWS (`alg: none`), and a JWS without a protected header.
- Signing a JWS in a JSON serialization. `parseJws` and `verifyJwsSignature` read the flattened and general JSON serializations, but `signCompactJws` produces the compact serialization only.
- An unencoded payload (`b64: false`) that is not valid UTF-8.

## Platform Support

This library is **platform agnostic** and works in:

- ✅ Node.js (>=20)
- ✅ Browsers (modern browsers with ES2020 support)
- ✅ React Native

## Contributing

See the [Contributing Guide](https://github.com/openwallet-foundation-labs/identity-common-ts/blob/main/CONTRIBUTING.md) for details on how to contribute to this project.

## License

This project is licensed under the [Apache License Version 2.0](https://github.com/openwallet-foundation-labs/identity-common-ts/blob/main/LICENSE) (Apache-2.0).
