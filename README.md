<h1 align="center">Identity Common - TypeScript</h1>

<p align="center">
  <a href="https://typescriptlang.org">
    <img src="https://img.shields.io/badge/%3C%2F%3E-TypeScript-%230074c1.svg" alt="TypeScript" />
  </a>
  <a href="https://github.com/openwallet-foundation-labs/identity-common-ts/blob/main/LICENSE">
    <img src="https://img.shields.io/badge/License-Apache%202.0-blue.svg" alt="Apache 2.0 License" />
  </a>
</p>

<p align="center">
  <a href="#overview">Overview</a>
  &nbsp;|&nbsp;
  <a href="#packages">Packages</a>
  &nbsp;|&nbsp;
  <a href="#getting-started">Getting Started</a>
  &nbsp;|&nbsp;
  <a href="#supported-environments">Supported Environments</a>
  &nbsp;|&nbsp;
  <a href="#contributing">Contributing</a>
  &nbsp;|&nbsp;
  <a href="#license">License</a>
</p>

---

## Overview

To avoid reinventing the wheel, many identity projects share common needs for data types and utility functions. **Identity Common TypeScript** provides a shared library of TypeScript types and utilities for identity-related projects, promoting consistency and reducing duplication across the ecosystem.

### Goals

- 🪶 **Lightweight**: Minimal dependencies to keep bundle sizes small
- 🌐 **Platform Agnostic**: Works in Node.js, browsers, and React Native
- 🔄 **Reusable**: Common utilities shared across identity solutions
- 🤝 **Interoperable**: Ensures compatibility between different identity projects

### Project Categories

The project is organized into two main categories:

#### Core Identity Utilities

Generic, reusable utilities that can be used across any identity solution:

| Package | Description | Status |
|---------|-------------|--------|
| [`@owf/identity-common`](./packages/identity-common) | Base types, base64url utilities, and JWT decoding | ✅ Available |
| [`@owf/crypto`](./packages/crypto) | Web Crypto API wrappers + SHA hash functions (`@noble/hashes`) | ✅ Available |
| [`@owf/token-status-list`](./packages/token-status-list) | Status list bitstring handling, JWT and CWT/CBOR transport | ✅ Available |
| `@owf/jose` | JOSE/JWT implementation with common validation methods | 📋 Planned |
| `@owf/cose` | COSE/CWT implementation with common validation methods | 📋 Planned |
| `@owf/x509` | X.509 certificate parsing, creation, and verification | 📋 Planned |

#### EUDI-Specific Tools

Tools specific to the [European Digital Identity (EUDI) Wallet](https://ec.europa.eu/digital-building-blocks/sites/display/EUDIGITALIDENTITYWALLET) ecosystem:

| Package | Description | Status |
|---------|-------------|--------|
| [`@owf/eudi-lote`](./packages/eudi-lote) | ETSI TS 119 602 Lists of Trusted Entities (LoTE) | ✅ Available |
| [`@owf/eudi-wrprc`](./packages/eudi-wrprc) | ETSI TS 119 475 Wallet-Relying Party Registration Certificates | ✅ Available |
| [`@owf/eudi-attestation-schema`](./packages/eudi-attestation-schema) | TS11 Catalogue of Attestations SchemaMeta | ✅ Available |
| `@owf/eudi-certificates` | Registration and access certificate verification | 📋 Planned |
| `@owf/eudi-sca` | TS12 Strong Customer Authentication Payments according to the latest to-be-added ARF |  In Progess |

> **Note**: While the EUDI Wallet is built on open standards (OpenID4VC, SD-JWT VC), it requires specific extensions for Trust, Payments, and document signing that are better suited in dedicated packages.

---

## Packages

### @owf/identity-common

[![@owf/identity-common version](https://img.shields.io/npm/v/@owf/identity-common)](https://npmjs.com/package/@owf/identity-common)

Base types (`JwtPayload`, `JsonWebKey`, `Signer`, `Verifier`, `Hasher`), base64url encode/decode, and JWT decoding.

```bash
npm install @owf/identity-common
```

📖 [View package documentation](./packages/identity-common/README.md)

### @owf/crypto

[![@owf/crypto version](https://img.shields.io/npm/v/@owf/crypto)](https://npmjs.com/package/@owf/crypto)

Web Crypto API wrappers for signing, hashing, salt generation, and ES256/384/512 key pairs, plus SHA-256/384/512 hash functions powered by `@noble/hashes`.

```bash
npm install @owf/crypto
```

📖 [View package documentation](./packages/crypto/README.md)

### @owf/token-status-list

[![@owf/token-status-list version](https://img.shields.io/npm/v/@owf/token-status-list)](https://npmjs.com/package/@owf/token-status-list)

Status list implementation with bitstring handling, compression/decompression, JWT transport layer, and CWT/CBOR transport layer for Token Status Lists (draft-ietf-oauth-status-list).

```bash
npm install @owf/token-status-list
```

📖 [View package documentation](./packages/token-status-list/README.md)

### @owf/eudi-lote

[![@owf/eudi-lote version](https://img.shields.io/npm/v/@owf/eudi-lote)](https://npmjs.com/package/@owf/eudi-lote)

SDK for creating, signing, and validating Lists of Trusted Entities (LoTE) per ETSI TS 119 602.

```bash
npm install @owf/eudi-lote
```

📖 [View package documentation](./packages/eudi-lote/README.md)

### @owf/eudi-wrprc

[![@owf/eudi-wrprc version](https://img.shields.io/npm/v/@owf/eudi-wrprc)](https://npmjs.com/package/@owf/eudi-wrprc)

SDK for creating, signing, and validating Wallet-Relying Party Registration Certificates (WRPRC) per ETSI TS 119 475 v1.2.1.

```bash
npm install @owf/eudi-wrprc
```

📖 [View package documentation](./packages/eudi-wrprc/README.md)

### @owf/eudi-attestation-schema

[![@owf/eudi-attestation-schema version](https://img.shields.io/npm/v/@owf/eudi-attestation-schema)](https://npmjs.com/package/@owf/eudi-attestation-schema)

SDK for creating, signing, and validating attestation schema metadata (SchemaMeta) per the EUDI TS11 Catalogue of Attestations specification.

```bash
npm install @owf/eudi-attestation-schema
```

📖 [View package documentation](./packages/eudi-attestation-schema/README.md)

---

## Getting Started

### Installation

Install the packages you need:

```bash
# Using npm
npm install @owf/identity-common

# Using pnpm
pnpm add @owf/identity-common

# Using yarn
yarn add @owf/identity-common
```

### Development Setup

This monorepo uses [pnpm](https://pnpm.io) for package management and [Turborepo](https://turbo.build/repo) for task orchestration.

```bash
# Clone the repository
git clone https://github.com/openwallet-foundation-labs/identity-common-ts.git
cd identity-common-ts

# Install dependencies (requires pnpm)
pnpm install

# Build all packages
pnpm build

# Run all tests
pnpm test
```

### Turborepo

All build and test tasks run through **Turborepo**, which provides:

- **Caching** — tasks whose inputs haven't changed are skipped entirely (a cached full run completes in ~15ms)
- **Parallelism** — independent packages build and test concurrently
- **Correct ordering** — packages are always built before the packages that depend on them

#### Task pipeline

| Task | Depends on | What it does |
|------|-----------|--------------|
| `build` | upstream `build` | Compiles each package with `tsdown` (ESM + CJS + `.d.ts`) |
| `test` | upstream `build` | Runs `vitest` tests for each package |
| `types:check` | upstream `build` | Type-checks the workspace with `tsc --noEmit` |
| `esm:check` | local `build` | Validates ESM import paths |
| `lint` | — | Linting (no build prerequisite) |

Run any task across all packages:

```bash
pnpm build          # turbo run build
pnpm test           # turbo run test

# Scope to a single package
npx turbo run build --filter=@owf/identity-common
npx turbo run test  --filter=@owf/crypto
```

The first run executes everything. Subsequent runs that find no changed inputs print `FULL TURBO` and finish instantly.

#### Cache details

Turbo computes a hash for each task from its **input files** (`src/**`, `package.json`, `tsconfig.json`), the global config (`tsconfig.json`, `vite.config.js`), and the pnpm lockfile. If the hash matches a previously-stored result the task is restored from `.turbo/cache/` without re-running.

The `.turbo/` directory is intentionally **not committed** (`.gitignore`) — every developer gets their own local cache.

---

## Supported Environments

This library is **platform agnostic** and supports:

- ✅ **Node.js** (>=20)
- ✅ **Browsers** (modern browsers with ES2020 support)
- ✅ **React Native**

### Requirements

Your environment must provide:

- `URL` and `URLSearchParams` implementations
- A global `fetch` implementation (or provide it via callbacks)

### Platform-Agnostic Design

Because these libraries are platform agnostic, cryptographic operations and other platform-specific functionality must be provided via callbacks:

```typescript
import { someFunction } from '@owf/identity-common'

// Provide platform-specific implementations
const result = await someFunction({
  crypto: {
    sha256: async (data) => { /* your implementation */ },
    randomBytes: (length) => { /* your implementation */ },
  },
  fetch: globalThis.fetch, // if not globally available
})
```

---

## Related Projects

This library is designed to work with and support other OpenWallet Foundation projects:

- [**sd-jwt-js**](https://github.com/openwallet-foundation-labs/sd-jwt-js) - SD-JWT implementation
- [**oid4vc-ts**](https://github.com/openwallet-foundation-labs/oid4vc-ts) - OpenID4VC implementation
- [**openid-federation-ts**](https://github.com/openwallet-foundation-labs/openid-federation-ts) - OpenID Federation implementation
- [**credo-ts**](https://github.com/openwallet-foundation/credo-ts) - Aries Framework JavaScript
- [**EUDIPLO**](https://github.com/openwallet-foundation-labs/eudiplo) - EUDI Wallet implementation

---

## Contributing

We welcome contributions! Whether you're:

- 🐛 Reporting bugs
- 💡 Suggesting features
- 📝 Improving documentation
- 🔧 Submitting code changes

Please read our [Contributing Guide](./CONTRIBUTING.md) to get started.

### Adding a New Package

A script is provided to scaffold a new package with the correct structure, build config, and Turborepo wiring already in place:

```bash
pnpm create-package <name>           # e.g. jose
pnpm create-package <name> --eudi   # prefixes with eudi-
```

See the [guide for adding packages](./CONTRIBUTING.md#adding-a-new-package) for details.

---

## License

This project is licensed under the [Apache License Version 2.0](./LICENSE) (Apache-2.0).
