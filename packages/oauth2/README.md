# @openid4vc/oauth2

[![npm version](https://img.shields.io/npm/v/@openid4vc/oauth2)](https://npmjs.com/package/@openid4vc/oauth2)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://github.com/openwallet-foundation-labs/identity-common-ts/blob/main/LICENSE)

An implementation of the [OAuth 2.0 Authorization Framework](https://datatracker.ietf.org/doc/html/rfc6749), including extension specifications:

- [RFC 9126 - OAuth 2.0 Pushed Authorization Requests](https://datatracker.ietf.org/doc/html/rfc9126)
- [OAuth 2.0 for First-Party Applications - Draft 0](https://www.ietf.org/archive/id/draft-ietf-oauth-first-party-apps-00.html)
- [RFC 7636 - Proof Key for Code Exchange by OAuth Public Clients](https://datatracker.ietf.org/doc/html/rfc7636)
- [RFC 9449 - OAuth 2.0 Demonstrating Proof of Possession (DPoP)](https://datatracker.ietf.org/doc/html/rfc9449)
- [RFC 7662 - OAuth 2.0 Token Introspection](https://datatracker.ietf.org/doc/html/rfc7662)
- [RFC 9068 JSON Web Token (JWT) Profile for OAuth 2.0 Access Tokens](https://datatracker.ietf.org/doc/html/rfc9068)
- [RFC 8707 - Resource Indicators for OAuth 2.0](https://www.rfc-editor.org/rfc/rfc8707.html)
- [OAuth 2.0 Attestation-Based Client Authentication](https://www.ietf.org/archive/id/draft-ietf-oauth-attestation-based-client-auth-09.html)
- [RFC 9207 - OAuth 2.0 Authorization Server Issuer Identification](https://www.rfc-editor.org/rfc/rfc9207.html)

This package was previously developed in the [oid4vc-ts](https://github.com/openwallet-foundation-labs/oid4vc-ts) repository. The `@openid4vc/*` packages are versioned together, separately from the other packages in this repository.

## Installation

```bash
# Using npm
npm install @openid4vc/oauth2

# Using pnpm
pnpm add @openid4vc/oauth2

# Using yarn
yarn add @openid4vc/oauth2
```

## Usage

```ts
import { Oauth2AuthorizationServer, Oauth2Client, Oauth2ResourceServer } from '@openid4vc/oauth2'
```

## Dependencies

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
