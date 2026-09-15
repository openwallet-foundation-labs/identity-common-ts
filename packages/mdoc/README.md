# @owf/mdoc

[![npm version](https://img.shields.io/npm/v/@owf/mdoc)](https://npmjs.com/package/@owf/mdoc)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://github.com/openwallet-foundation-labs/identity-common-ts/blob/main/LICENSE)

Implementation of [ISO/IEC 18013-5](https://www.iso.org/standard/69084.html) mDOC and mDL (mobile driving licence) documents for Node.js, browsers and React Native. Issue, hold, present and verify [CBOR encoded](https://cbor.io/) documents, including the presentation flows of ISO/IEC 18013-7 and OpenID4VP.

This package was previously developed in the [mdoc-ts](https://github.com/openwallet-foundation-labs/mdoc-ts) repository. It is versioned separately from the other `@owf/*` packages.

## Installation

```bash
# Using npm
npm install @owf/mdoc

# Using pnpm
pnpm add @owf/mdoc

# Using yarn
yarn add @owf/mdoc
```

## Usage

The `Issuer`, `Holder` and `Verifier` classes cover issuing, presenting and verifying mDOCs. Cryptographic operations, X.509 certificate handling and `fetch` are provided through an `MdocContext`. See the [tests](https://github.com/openwallet-foundation-labs/identity-common-ts/tree/main/packages/mdoc/src/__tests__) for complete flows, and an example `MdocContext` in [`context.ts`](https://github.com/openwallet-foundation-labs/identity-common-ts/blob/main/packages/mdoc/src/__tests__/context.ts).

## Dependencies

- [@owf/cose](https://www.npmjs.com/package/@owf/cose)
- [@owf/identity-common](https://www.npmjs.com/package/@owf/identity-common)
- [@owf/token-status-list](https://www.npmjs.com/package/@owf/token-status-list)
- [zod](https://www.npmjs.com/package/zod)

## Platform Support

This library is **platform agnostic** and works in:

- ✅ Node.js (>=22)
- ✅ Browsers (modern browsers with ES2020 support)
- ✅ React Native

A global `TextEncoder` and `TextDecoder` must be available. See the [React Native notes](https://github.com/openwallet-foundation-labs/identity-common-ts/blob/main/packages/identity-common/README.md#react-native) if you need a polyfill.

## Contributing

See the [Contributing Guide](https://github.com/openwallet-foundation-labs/identity-common-ts/blob/main/CONTRIBUTING.md) for details on how to contribute to this project.

## License

This project is licensed under the [Apache License Version 2.0](https://github.com/openwallet-foundation-labs/identity-common-ts/blob/main/LICENSE) (Apache-2.0).

## Credits

Thanks to:

- [auth0/mdl](https://github.com/auth0-lab/mdl) for the mdl implementation on which this package is based.
- [auer-martin](https://github.com/auer-martin) for removing Node.js dependencies and providing a pluggable crypto interface.
