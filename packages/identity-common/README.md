# @owf/identity-common

[![npm version](https://img.shields.io/npm/v/@owf/identity-common)](https://npmjs.com/package/@owf/identity-common)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://github.com/openwallet-foundation-labs/identity-common-ts/blob/main/LICENSE)

The base package of the [Identity Common TypeScript](https://github.com/openwallet-foundation-labs/identity-common-ts) project, providing common types and utilities for identity applications.

## Installation

```bash
# Using npm
npm install @owf/identity-common

# Using pnpm
pnpm add @owf/identity-common

# Using yarn
yarn add @owf/identity-common
```

## Usage

```typescript
import { } from '@owf/identity-common'
```

## Platform Support

This library is **platform agnostic** and works in:

- ✅ Node.js (>=20)
- ✅ Browsers (modern browsers with ES2020 support)
- ✅ React Native

### Requirements

Your environment must provide:

- `URL` and `URLSearchParams` implementations
- A global `fetch` implementation (or provide it via callbacks)
- Global `TextEncoder` and `TextDecoder` implementations

### React Native

When using these libraries in React Native you may need to add a polyfill for `TextDecoder`.

You can confirm this by checking if `global.TextDecoder` is available. It should be available for React Native > 0.85 or Expo SDK > 52.

If it is not available, make sure to add a polyfill like [this one](https://github.com/EvanBacon/text-decoder).

## API Reference

*Documentation will be added as the API is developed.*

## Related Packages

This package is part of the Identity Common TypeScript project:

- `@owf/jose` - JOSE/JWT implementation (planned)
- [`@owf/cose`](https://github.com/openwallet-foundation-labs/identity-common-ts/tree/main/packages/cose) - COSE/CWT implementation (planned)
- `@owf/x509` - X.509 certificate utilities (planned)

## Contributing

See the [Contributing Guide](https://github.com/openwallet-foundation-labs/identity-common-ts/blob/main/CONTRIBUTING.md) for details on how to contribute to this project.

## License

This project is licensed under the [Apache License Version 2.0](https://github.com/openwallet-foundation-labs/identity-common-ts/blob/main/LICENSE) (Apache-2.0).
