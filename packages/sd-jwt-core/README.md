# @sd-jwt/core

[![npm version](https://img.shields.io/npm/v/@sd-jwt/core)](https://npmjs.com/package/@sd-jwt/core)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://github.com/openwallet-foundation-labs/identity-common-ts/blob/main/LICENSE)

Core library for [Selective Disclosure for JWTs (SD-JWT) — RFC 9901](https://www.rfc-editor.org/rfc/rfc9901.html).

This package provides types, utilities, encoding/decoding, presentation, and the main `SDJwtInstance` class — everything needed to issue, present, and verify SD-JWTs. For [SD-JWT-based Verifiable Credentials](https://datatracker.ietf.org/doc/draft-ietf-oauth-sd-jwt-vc/), use [`@sd-jwt/sd-jwt-vc`](../sd-jwt-vc), which is built on top of this package.

## Installation

```bash
# Using npm
npm install @sd-jwt/core

# Using pnpm
pnpm add @sd-jwt/core

# Using yarn
yarn add @sd-jwt/core
```

## Quick Start

```typescript
import Crypto from 'node:crypto'
import { SDJwtInstance } from '@sd-jwt/core'

// Bring your own crypto – any Signer / Verifier / Hasher that fits the interface
const { privateKey, publicKey } = Crypto.generateKeyPairSync('ed25519')

const sdjwt = new SDJwtInstance({
  signer: async (data) => {
    const sig = Crypto.sign(null, Buffer.from(data), privateKey)
    return Buffer.from(sig).toString('base64url')
  },
  verifier: async (data, sig) => {
    return Crypto.verify(null, Buffer.from(data), publicKey, Buffer.from(sig, 'base64url'))
  },
  signAlg: 'EdDSA',
  hasher: async (data, alg) => {
    return new Uint8Array(Crypto.createHash(alg.replace('-', '')).update(data).digest())
  },
  hashAlg: 'sha-256',
  saltGenerator: async () => Crypto.randomBytes(16).toString('base64url'),
})

// Issue
const credential = await sdjwt.issue(
  { firstname: 'John', lastname: 'Doe', ssn: '123-45-6789' },
  { _sd: ['firstname', 'lastname', 'ssn'] }
)

// Present (disclose only firstname)
const presentation = await sdjwt.present(credential, { firstname: true })

// Verify
const { payload } = await sdjwt.verify(presentation)
console.log(payload) // { firstname: 'John', ... }
```

## Examples

Runnable examples are available in [`examples/sd-jwt/core`](../../examples/sd-jwt/core). Run them from the repository root:

```bash
pnpm tsx examples/sd-jwt/core/basic.ts
```

See the [SD-JWT examples overview](../../examples/sd-jwt/README.md) for the full list.

## Security

- [x] [Mandatory Signing of the Issuer-signed JWT](https://www.rfc-editor.org/rfc/rfc9901.html#name-mandatory-signing-of-the-is)
- [x] [Manipulation of Disclosures](https://www.rfc-editor.org/rfc/rfc9901.html#name-manipulation-of-disclosures)
- [x] [Entropy of the salt](https://www.rfc-editor.org/rfc/rfc9901.html#name-entropy-of-the-salt)
- [x] [Minimum length of the salt](https://www.rfc-editor.org/rfc/rfc9901.html#name-minimum-length-of-the-salt)
- [x] [Choice of a Hash Algorithm](https://www.rfc-editor.org/rfc/rfc9901.html#name-choice-of-a-hash-algorithm)
- [x] [Key Binding](https://www.rfc-editor.org/rfc/rfc9901.html#name-key-binding)
- [x] [Blinding Claim Names](https://www.rfc-editor.org/rfc/rfc9901.html#name-blinding-claim-names)
- [x] [Selectively-Disclosable Validity Claims](https://www.rfc-editor.org/rfc/rfc9901.html#name-selectively-disclosable-val)
- [x] [Issuer Signature Key Distribution and Rotation](https://www.rfc-editor.org/rfc/rfc9901.html#name-issuer-signature-key-distri)
- [x] [Forwarding Credentials](https://www.rfc-editor.org/rfc/rfc9901.html#name-forwarding-credentials)
- [x] [Integrity of Presentation](https://www.rfc-editor.org/rfc/rfc9901.html#name-integrity-of-presentation)
- [x] [Explicit Typing](https://www.rfc-editor.org/rfc/rfc9901.html#name-explicit-typing)
- [x] [Duplicate Digest Rejection (Section 7.1 step 4)](https://www.rfc-editor.org/rfc/rfc9901.html#section-7.1)
- [x] [Unreferenced Disclosure Rejection (Section 7.1 step 5)](https://www.rfc-editor.org/rfc/rfc9901.html#section-7.1)
- [x] [Claim Name Collision Detection (Section 7.1 step 3c.ii.3)](https://www.rfc-editor.org/rfc/rfc9901.html#section-7.1)

## Platform Support

This library is **platform agnostic** and works in:

- ✅ Node.js (>=20)
- ✅ Browsers (modern browsers with ES2020 support)
- ✅ React Native

A global `TextEncoder` and `TextDecoder` must be available. See the [React Native notes](../identity-common/README.md#react-native) if you need a polyfill.

Cryptographic operations (signing, verification, hashing, salt generation) are provided as callbacks. [`@owf/crypto`](https://github.com/openwallet-foundation-labs/identity-common-ts/tree/main/packages/crypto) provides Web Crypto based implementations.

## Contributing

See the [Contributing Guide](https://github.com/openwallet-foundation-labs/identity-common-ts/blob/main/CONTRIBUTING.md) for details on how to contribute to this project.

## License

This project is licensed under the [Apache License Version 2.0](https://github.com/openwallet-foundation-labs/identity-common-ts/blob/main/LICENSE) (Apache-2.0).
