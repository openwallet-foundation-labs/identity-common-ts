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

The project is organized into six main categories:

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
| [`@owf/eudi-tl`](./packages/eudi-tl) | ETSI TS 119 612 XML Trusted Lists parsing and verification | ✅ Available |
| [`@owf/eudi-wrprc`](./packages/eudi-wrprc) | ETSI TS 119 475 Wallet-Relying Party Registration Certificates | ✅ Available |
| [`@owf/eudi-attestation-schema`](./packages/eudi-attestation-schema) | TS11 Catalogue of Attestations SchemaMeta | ✅ Available |
| `@owf/eudi-certificates` | Registration and access certificate verification | 📋 Planned |
| `@owf/eudi-sca` | TS12 Strong Customer Authentication Payments according to the latest to-be-added ARF |  In Progess |

#### SD-JWT

Implementations of [Selective Disclosure for JWTs (SD-JWT)](https://www.rfc-editor.org/rfc/rfc9901.html) and [SD-JWT-based Verifiable Credentials (SD-JWT VC)](https://datatracker.ietf.org/doc/draft-ietf-oauth-sd-jwt-vc/), previously developed in [sd-jwt-js](https://github.com/openwallet-foundation/sd-jwt-js). The `@sd-jwt/*` packages are versioned separately from the `@owf/*` packages.

| Package | Description | Status |
|---------|-------------|--------|
| [`@sd-jwt/core`](./packages/sd-jwt-core) | SD-JWT (RFC 9901) issuance, presentation, and verification | ✅ Available |
| [`@sd-jwt/sd-jwt-vc`](./packages/sd-jwt-vc) | SD-JWT VC (draft-ietf-oauth-sd-jwt-vc) built on top of `@sd-jwt/core` | ✅ Available |

#### mDOC

Implementation of [ISO/IEC 18013-5](https://www.iso.org/standard/69084.html) mDOC and mDL (mobile driving licence) documents, including the ISO/IEC 18013-7 and OpenID4VP presentation flows, previously developed in [mdoc-ts](https://github.com/openwallet-foundation-labs/mdoc-ts). `@owf/mdoc` is versioned separately from the other `@owf/*` packages.

| Package | Description | Status |
|---------|-------------|--------|
| [`@owf/mdoc`](./packages/mdoc) | ISO/IEC 18013-5 mDOC and mDL issuance, presentation, and verification | ✅ Available |

#### DCQL

Implementation of the [Digital Credentials Query Language (DCQL)](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-digital-credentials-query-l) from OpenID4VP, previously developed in [dcql-ts](https://github.com/openwallet-foundation-labs/dcql-ts). `dcql` is versioned separately from the other packages.

| Package | Description | Status |
|---------|-------------|--------|
| [`dcql`](./packages/dcql) | Create, validate, and execute DCQL queries, and validate presentations against them | ✅ Available |

#### OpenID4VC

Implementations of OAuth 2.0, [OpenID for Verifiable Credential Issuance (OpenID4VCI)](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html) and [OpenID for Verifiable Presentations (OpenID4VP)](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html), previously developed in [oid4vc-ts](https://github.com/openwallet-foundation-labs/oid4vc-ts). The `@openid4vc/*` packages are versioned together, separately from the other packages.

| Package | Description | Status |
|---------|-------------|--------|
| [`@openid4vc/oauth2`](./packages/oauth2) | OAuth 2.0 client, authorization server and resource server, including PAR, PKCE, DPoP, JAR and attestation-based client authentication | ✅ Available |
| [`@openid4vc/openid4vci`](./packages/openid4vci) | OpenID4VCI issuer and client, from draft 11 up to 1.0 | ✅ Available |
| [`@openid4vc/openid4vp`](./packages/openid4vp) | OpenID4VP verifier and client, from draft 18 up to 1.0 | ✅ Available |
| [`@openid4vc/utils`](./packages/openid4vc-utils) | Shared utilities for the `@openid4vc/*` packages | ✅ Available |

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

### @owf/eudi-tl

[![@owf/eudi-tl version](https://img.shields.io/npm/v/@owf/eudi-tl)](https://npmjs.com/package/@owf/eudi-tl)

Parsing, validation, and XAdES signature verification for ETSI TS 119 612 XML Trusted Lists, exposing normalized trust anchors. The XML counterpart of `@owf/eudi-lote`.

```bash
npm install @owf/eudi-tl
```

📖 [View package documentation](./packages/eudi-tl/README.md)

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

### @sd-jwt/core

[![@sd-jwt/core version](https://img.shields.io/npm/v/@sd-jwt/core)](https://npmjs.com/package/@sd-jwt/core)

Core library for SD-JWT (RFC 9901): encoding, decoding, selective disclosure, presentation, key binding, and verification.

```bash
npm install @sd-jwt/core
```

📖 [View package documentation](./packages/sd-jwt-core/README.md)

### @sd-jwt/sd-jwt-vc

[![@sd-jwt/sd-jwt-vc version](https://img.shields.io/npm/v/@sd-jwt/sd-jwt-vc)](https://npmjs.com/package/@sd-jwt/sd-jwt-vc)

SD-JWT VC implementation built on top of `@sd-jwt/core`, with status list (revocation) and type metadata validation.

```bash
npm install @sd-jwt/sd-jwt-vc
```

📖 [View package documentation](./packages/sd-jwt-vc/README.md)

### @owf/mdoc

[![@owf/mdoc version](https://img.shields.io/npm/v/@owf/mdoc)](https://npmjs.com/package/@owf/mdoc)

ISO/IEC 18013-5 mDOC and mDL: issue, hold, present, and verify CBOR encoded documents, with support for ISO/IEC 18013-7 and OpenID4VP session transcripts.

```bash
npm install @owf/mdoc
```

📖 [View package documentation](./packages/mdoc/README.md)

### dcql

[![dcql version](https://img.shields.io/npm/v/dcql)](https://npmjs.com/package/dcql)

Digital Credentials Query Language (DCQL): create and validate queries, match them against credentials, and validate presentation results. Supports `mso_mdoc`, `dc+sd-jwt` and W3C VC formats, from OpenID4VP Draft 22 up to 1.0.

```bash
npm install dcql
```

📖 [View package documentation](./packages/dcql/README.md)

### @openid4vc/oauth2

[![@openid4vc/oauth2 version](https://img.shields.io/npm/v/@openid4vc/oauth2)](https://npmjs.com/package/@openid4vc/oauth2)

OAuth 2.0 Authorization Framework implementation, including Pushed Authorization Requests, PKCE, DPoP, token introspection, JWT access tokens, resource indicators and attestation-based client authentication.

```bash
npm install @openid4vc/oauth2
```

📖 [View package documentation](./packages/oauth2/README.md)

### @openid4vc/openid4vci

[![@openid4vc/openid4vci version](https://img.shields.io/npm/v/@openid4vc/openid4vci)](https://npmjs.com/package/@openid4vc/openid4vci)

OpenID for Verifiable Credential Issuance: authorization code and pre-authorized code flows, credential offers, signed issuer metadata, key attestations and presentation during issuance. Supports 1.0 with backwards compatibility down to draft 11.

```bash
npm install @openid4vc/openid4vci
```

📖 [View package documentation](./packages/openid4vci/README.md)

### @openid4vc/openid4vp

[![@openid4vc/openid4vp version](https://img.shields.io/npm/v/@openid4vc/openid4vp)](https://npmjs.com/package/@openid4vc/openid4vp)

OpenID for Verifiable Presentations: signed and unsigned requests (JAR), `direct_post`, `direct_post.jwt`, `dc_api` and `dc_api.jwt` response modes, JARM and transaction data. Supports 1.0 with backwards compatibility down to draft 18.

```bash
npm install @openid4vc/openid4vp
```

📖 [View package documentation](./packages/openid4vp/README.md)

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

This monorepo uses [pnpm workspaces](https://pnpm.io/workspaces).

```bash
# Clone the repository
git clone https://github.com/openwallet-foundation-labs/identity-common-ts.git
cd identity-common-ts

# Install dependencies (requires pnpm)
pnpm install

# Run all tests, or a subset
pnpm test
pnpm test packages/mdoc

# Type-check the workspace
pnpm types:check

# Build all packages with tsdown
pnpm build
```

Within the workspace, packages export their TypeScript source, so tests, type checks, and examples run without a build. The built `dist` entrypoints are configured in `publishConfig` and only used for the published packages. See the [Contributing Guide](./CONTRIBUTING.md) for all available scripts.

---

## Supported Environments

This library is **platform agnostic** and supports:

- ✅ **Node.js** (>=22)
- ✅ **Browsers** (modern browsers with ES2020 support)
- ✅ **React Native**

### Requirements

Your environment must provide:

- `URL` and `URLSearchParams` implementations
- A global `fetch` implementation (or provide it via callbacks)
- Global `TextEncoder` and `TextDecoder` implementations

### React Native

When using these libraries in React Native you may need to add a polyfill for `TextDecoder`.

You can confirm this by checking if `global.TextDecoder` is available. It should be available for React Native > 0.85 or Expo SDK > 52.

If it is not available, make sure to add a polyfill like [this one](https://github.com/EvanBacon/text-decoder).

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

A script is provided to scaffold a new package with the correct structure and build config already in place:

```bash
pnpm create-package <name>           # e.g. jose
pnpm create-package <name> --eudi   # prefixes with eudi-
```

See the [guide for adding packages](./CONTRIBUTING.md#adding-a-new-package) for details.

---

## License

This project is licensed under the [Apache License Version 2.0](./LICENSE) (Apache-2.0).
