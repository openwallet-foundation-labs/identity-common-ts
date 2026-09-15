# @sd-jwt/sd-jwt-vc

[![npm version](https://img.shields.io/npm/v/@sd-jwt/sd-jwt-vc)](https://npmjs.com/package/@sd-jwt/sd-jwt-vc)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://github.com/openwallet-foundation-labs/identity-common-ts/blob/main/LICENSE)

Implementation of [SD-JWT-based Verifiable Credentials (SD-JWT VC) — draft-ietf-oauth-sd-jwt-vc-15](https://www.ietf.org/archive/id/draft-ietf-oauth-sd-jwt-vc-15.html), built on top of [`@sd-jwt/core`](../sd-jwt-core) ([RFC 9901](https://www.rfc-editor.org/rfc/rfc9901.html)).

## Installation

```bash
# Using npm
npm install @sd-jwt/sd-jwt-vc

# Using pnpm
pnpm add @sd-jwt/sd-jwt-vc

# Using yarn
yarn add @sd-jwt/sd-jwt-vc
```

## Usage

Here's a basic example of how to use this library:

```typescript
import type { DisclosureFrame } from '@sd-jwt/core';

// identifier of the issuer
const iss = 'University';

// issuance time
const iat = Math.floor(Date.now() / 1000); // current time in seconds

//unique identifier of the schema
const vct = 'University-Degree';

// Issuer defines the claims object with the user's information
const claims = {
  firstname: 'John',
  lastname: 'Doe',
  ssn: '123-45-6789',
  id: '1234',
};

// Issuer defines the disclosure frame to specify which claims can be disclosed/undisclosed
const disclosureFrame: DisclosureFrame<typeof claims> = {
  _sd: ['firstname', 'lastname', 'ssn'],
};

// Issuer issues a signed JWT credential with the specified claims and disclosure frame
// returns an encoded JWT
const credential = await sdjwt.issue(
  { iss, iat, vct, ...claims },
  disclosureFrame,
);

// Holder may validate the credential from the issuer
const valid = await sdjwt.validate(credential);

// Holder defines the presentation frame to specify which claims should be presented
// The list of presented claims must be a subset of the disclosed claims
const presentationFrame = { firstname: true, ssn: true };

// Holder creates a presentation using the issued credential and the presentation frame
// returns an encoded SD JWT.
const presentation = await sdjwt.present(credential, presentationFrame);

// Verifier can verify the presentation using the Issuer's public key
const verified = await sdjwt.verify(presentation);
```

## Examples

Runnable examples are available in [`examples/sd-jwt/sd-jwt-vc`](../../examples/sd-jwt/sd-jwt-vc). Run them from the repository root:

```bash
pnpm tsx examples/sd-jwt/sd-jwt-vc/basic.ts
```

See the [SD-JWT examples overview](../../examples/sd-jwt/README.md) for the full list.

## Dependencies

- [@sd-jwt/core](https://www.npmjs.com/package/@sd-jwt/core)
- [@owf/token-status-list](https://www.npmjs.com/package/@owf/token-status-list)
- [zod](https://www.npmjs.com/package/zod)

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
