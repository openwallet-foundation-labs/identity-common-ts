# @openid4vc/openid4vci

[![npm version](https://img.shields.io/npm/v/@openid4vc/openid4vci)](https://npmjs.com/package/@openid4vc/openid4vci)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://github.com/openwallet-foundation-labs/identity-common-ts/blob/main/LICENSE)

An implementation of the [OpenID for Verifiable Credential Issuance](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html) specification:

- Authorization Code Flow and Pre-Authorized Code Flow
- Credential format profiles `vc+sd-jwt`, `dc+sd-jwt`, `mso_mdoc`, `jwt_vc_json`, `jwt_vc_json-ld`, and `ldp_vc` (only object validation, no credential implementation)
- Proof type `jwt` and `attestation`
- V1.0 with backwards compatibility for draft 15, draft 14, draft 13 (ID1), and draft 11
- Support presentation during issuance using Authorization Challenge and OpenID4VP
- Create and verify wallet attestations based on attestation-based client authentication
- Resolve and create signed credential issuer metadata

This package was previously developed in the [oid4vc-ts](https://github.com/openwallet-foundation-labs/oid4vc-ts) repository. The `@openid4vc/*` packages are versioned together, separately from the other packages in this repository.

## Installation

```bash
# Using npm
npm install @openid4vc/openid4vci

# Using pnpm
pnpm add @openid4vc/openid4vci

# Using yarn
yarn add @openid4vc/openid4vci
```

## Usage

```ts
import { Openid4vciClient, Openid4vciIssuer } from '@openid4vc/openid4vci'
```

### Credential Request encryption

An issuer advertises `credential_request_encryption` in its Credential Issuer
Metadata, including its public `jwks`, supported `enc` values, and
`encryption_required`. The client needs an `encryptJwe` callback to encrypt
requests; the issuer needs a `decryptJwe` callback to handle encrypted requests.
Keep the issuer's private decryption keys on the issuer side. If encryption is
not required and the request does not ask for response encryption, the client
continues to send JSON. The following snippets assume the other required
callbacks, issuer metadata, and credential values have already been provided.
The client's callbacks include `decryptJwe` for encrypted responses, and the
issuer's callbacks include `encryptJwe` for producing them.

```ts
const client = new Openid4vciClient({
  callbacks: { ...clientCallbacks, encryptJwe },
})

await client.retrieveCredentials({
  issuerMetadata,
  accessToken,
  credentialConfigurationId,
  credentialRequestEncryption: {}, // Optional: can also select an advertised kid and enc
})
```

The same `credentialRequestEncryption` option is available on
`retrieveDeferredCredentials`. Encryption is automatic when the issuer requires
it or the request contains `credential_response_encryption`. To request
response encryption, supply `credentialResponseEncryption` with the wallet's
public JWK (including `alg`) and `enc`; the wallet also needs a `decryptJwe`
callback to read the encrypted response. A deferred request can supply a fresh
response-encryption key. The client encrypts requests when required by the
issuer or when V1 response-encryption parameters require it, and fails before
sending if request encryption is required but unsupported or unavailable.

For **both** Credential and Deferred Credential HTTP endpoints, pass the
transport body and content type to the issuer library for decoding and validation:

```ts
const issuer = new Openid4vciIssuer({
  callbacks: { ...issuerCallbacks, decryptJwe },
})

// requestBody is raw JSON text for application/json or a compact JWE string
// for application/jwt; contentType is the HTTP Content-Type.
const parsed = await issuer.parseCredentialRequestFromBody({
  body: requestBody,
  contentType,
  issuerMetadata,
})
const { credentialResponse, credentialResponseJwt } = await issuer.createCredentialResponse({
  credentialRequest: parsed,
  credential: issuedCredential,
  credentialResponseEncryption: parsed.credentialResponseEncryption,
})
// Send credentialResponseJwt with application/jwt when defined;
// otherwise send credentialResponse with application/json.
```

At the deferred endpoint, pass the raw body and content type to
`parseDeferredCredentialRequestFromBody`. Pass the parsed request's
`credential_response_encryption` to `createDeferredCredentialResponse`.
The body parsing methods decode raw JSON text or decrypt JWE requests, then
validate the request. Already-parsed JSON objects are also accepted for
`application/json`. HTTP adapters only need to read the body and preserve JWE
strings; they do not need to implement protocol-specific decryption or validation.
The synchronous `parseCredentialRequest` and `parseDeferredCredentialRequest`
methods remain available for already-decoded objects, but are deprecated in
favor of the body parsing methods.
The body parsing methods reject plaintext requests when the issuer requires
request encryption, or when response-encryption parameters require an encrypted
request for V1 or an issuer advertising request encryption. Credential request and
response encryption do not support compression: requests with a `zip` header
and response-encryption parameters with `zip` are rejected, even when the
issuer advertises the value. Issuers must not advertise compression until it
is implemented.
The client never compresses requests.

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
