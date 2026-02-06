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

- ✅ Node.js (>=22)
- ✅ Browsers (modern browsers with ES2020 support)
- ✅ React Native

### Requirements

Your environment must provide:

- `URL` and `URLSearchParams` implementations
- A global `fetch` implementation (or provide it via callbacks)

## API Reference

*Documentation will be added as the API is developed.*

## Related Packages

This package is part of the Identity Common TypeScript project:

- [`@owf/jose`](https://github.com/openwallet-foundation-labs/identity-common-ts/tree/main/packages/jose) - JOSE/JWT implementation (planned)
- [`@owf/cose`](https://github.com/openwallet-foundation-labs/identity-common-ts/tree/main/packages/cose) - COSE/CWT implementation (planned)
- [`@owf/x509`](https://github.com/openwallet-foundation-labs/identity-common-ts/tree/main/packages/x509) - X.509 certificate utilities (planned)

## Contributing

See the [Contributing Guide](https://github.com/openwallet-foundation-labs/identity-common-ts/blob/main/CONTRIBUTING.md) for details on how to contribute to this project.

## License

This project is licensed under the [Apache License Version 2.0](https://github.com/openwallet-foundation-labs/identity-common-ts/blob/main/LICENSE) (Apache-2.0).
