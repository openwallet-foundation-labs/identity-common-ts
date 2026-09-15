# @openid4vc/openid4vp

[![npm version](https://img.shields.io/npm/v/@openid4vc/openid4vp)](https://npmjs.com/package/@openid4vc/openid4vp)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://github.com/openwallet-foundation-labs/identity-common-ts/blob/main/LICENSE)

An implementation of the [OpenID for Verifiable Presentations](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html) specification:

- Signed and unsigned requests
- Support for response mode `direct_post`, `direct_post.jwt`, `dc_api` and `dc_api.jwt`
- No out of the box support for Presentation Exchange or DCQL, this needs to be provided using e.g. [`dcql`](https://github.com/openwallet-foundation-labs/identity-common-ts/tree/main/packages/dcql) or [PEX](https://github.com/Sphereon-Opensource/PEX)
- Transaction Data
- V1.0 with backward compatibility until Draft 18
- Support for JWT Secured Authorization Request (JAR)
- Support for JWT Secure Authorization Response Mode (JARM)

This package was previously developed in the [oid4vc-ts](https://github.com/openwallet-foundation-labs/oid4vc-ts) repository. The `@openid4vc/*` packages are versioned together, separately from the other packages in this repository.

## Installation

```bash
# Using npm
npm install @openid4vc/openid4vp

# Using pnpm
pnpm add @openid4vc/openid4vp

# Using yarn
yarn add @openid4vc/openid4vp
```

## Usage

```ts
import { Openid4vpClient, Openid4vpVerifier } from '@openid4vc/openid4vp'
```

## Dependencies

- [@openid4vc/oauth2](https://www.npmjs.com/package/@openid4vc/oauth2)
- [@openid4vc/utils](https://www.npmjs.com/package/@openid4vc/utils)
- [zod](https://www.npmjs.com/package/zod)

## Platform Support

This library is **platform agnostic** and works in:

- ✅ Node.js (>=22)
- ✅ Browsers (modern browsers with ES2020 support)
- ✅ React Native

The environment must provide an implementation of `URL` and `URLSearchParams`. Platform-specific functionality such as hashing, generating random bytes and signing is provided through callbacks. If no global `fetch` is available in your environment, it also needs to be provided through the callbacks.

## Contributing

See the [Contributing Guide](https://github.com/openwallet-foundation-labs/identity-common-ts/blob/main/CONTRIBUTING.md) for details on how to contribute to this project.

## License

This project is licensed under the [Apache License Version 2.0](https://github.com/openwallet-foundation-labs/identity-common-ts/blob/main/LICENSE) (Apache-2.0).

## Credits

This library was initially created by [Animo](https://animo.id) as part of the [SPRIN-D EUDI Wallet Prototypes Funke](https://www.sprind.org/en/impulses/challenges/eudi-wallet-prototypes).
