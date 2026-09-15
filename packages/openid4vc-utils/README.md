# @openid4vc/utils

[![npm version](https://img.shields.io/npm/v/@openid4vc/utils)](https://npmjs.com/package/@openid4vc/utils)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://github.com/openwallet-foundation-labs/identity-common-ts/blob/main/LICENSE)

Shared utilities used by the `@openid4vc/*` packages, such as encoding helpers, validation errors, and platform-agnostic `fetch`, `URL` and `URLSearchParams` wrappers.

This package is mostly used internally by [`@openid4vc/oauth2`](https://github.com/openwallet-foundation-labs/identity-common-ts/tree/main/packages/oauth2), [`@openid4vc/openid4vci`](https://github.com/openwallet-foundation-labs/identity-common-ts/tree/main/packages/openid4vci) and [`@openid4vc/openid4vp`](https://github.com/openwallet-foundation-labs/identity-common-ts/tree/main/packages/openid4vp).

This package was previously developed in the [oid4vc-ts](https://github.com/openwallet-foundation-labs/oid4vc-ts) repository. The `@openid4vc/*` packages are versioned together, separately from the other packages in this repository.

## Installation

```bash
# Using npm
npm install @openid4vc/utils

# Using pnpm
pnpm add @openid4vc/utils

# Using yarn
yarn add @openid4vc/utils
```

## Dependencies

- [buffer](https://www.npmjs.com/package/buffer)
- [zod](https://www.npmjs.com/package/zod)
- [zod-validation-error](https://www.npmjs.com/package/zod-validation-error)

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
