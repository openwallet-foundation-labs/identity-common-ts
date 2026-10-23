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
  credentialRequestEncryption: { encrypt: true }, // Optional: can also select kid and enc
})
```

The same `credentialRequestEncryption` option is available on
`retrieveDeferredCredentials`. Encryption is automatic when the issuer requires
it or the request contains `credential_response_encryption`. To request
response encryption, supply `credentialResponseEncryption` with the wallet's
public JWK (including `alg`) and `enc`; the wallet also needs a `decryptJwe`
callback to read the encrypted response. A deferred request can supply a fresh
response-encryption key. The client refuses to send response-encryption
parameters in plaintext and fails before sending if the issuer does not
advertise request encryption or the client cannot encrypt.

For **both** Credential and Deferred Credential HTTP endpoints, decode the
transport body before parsing its contents:

```ts
const issuer = new Openid4vciIssuer({
  callbacks: { ...issuerCallbacks, decryptJwe },
})

// requestBody is a JWE string for application/jwt or an already-parsed
// JSON object for application/json; contentType is the HTTP Content-Type.
const { credentialRequest } = await issuer.decodeCredentialRequest({
  body: requestBody,
  contentType,
  issuerMetadata,
})
const parsed = issuer.parseCredentialRequest({ issuerMetadata, credentialRequest })
const { credentialResponse, credentialResponseJwt } = await issuer.createCredentialResponse({
  credentialRequest: parsed,
  credential: issuedCredential,
  credentialResponseEncryption: parsed.credentialResponseEncryption,
})
// Send credentialResponseJwt with application/jwt when defined;
// otherwise send credentialResponse with application/json.
```

At the deferred endpoint use `decodeDeferredCredentialRequest`, followed by
`parseDeferredCredentialRequest` and `createDeferredCredentialResponse`. Pass
the parsed request's `credential_response_encryption` to response creation.
Raw-request handlers **must** decode before parsing: parsers only validate
request objects and cannot determine whether the HTTP body was encrypted.
Decoding rejects plaintext requests containing `credential_response_encryption`
or sent to an issuer that requires request encryption. It also rejects
compressed (`zip`) requests even if `zip_values_supported` is present in
metadata; issuers must not advertise compression until it is implemented.
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
