# @owf/openid-federation

[![npm version](https://img.shields.io/npm/v/@owf/openid-federation)](https://npmjs.com/package/@owf/openid-federation)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://github.com/openwallet-foundation-labs/identity-common-ts/blob/main/LICENSE)

[OpenID Federation 1.0](https://openid.net/specs/openid-federation-1_0.html): create, fetch and validate entity
configurations and subordinate statements, resolve trust chains to trust anchors, and apply metadata policies.

Signing and signature verification are callbacks, so private keys never enter the package and can stay in WebCrypto, a
KMS or an HSM. The package uses neither Node.js built-ins nor global crypto, so it runs on servers, in browsers and in
React Native.

Previously published as `@openid-federation/core` from
[openid-federation-ts](https://github.com/openwallet-foundation-labs/openid-federation-ts).

## Installation

```bash
npm install @owf/openid-federation
```

## Callbacks

```typescript
import type { SignCallback, VerifyCallback } from '@owf/openid-federation'

// Called with the JWS signing input and the JWK of the `kid` in the header. Return the JWS signature.
const signJwtCallback: SignCallback = async ({ toBeSigned, jwk }) => {
  const privateKey = await getPrivateKey(jwk.kid)
  return new Uint8Array(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, privateKey, toBeSigned))
}

// Called with the JWS signing input, the signature and the JWK the statement must be signed with
const verifyJwtCallback: VerifyCallback = async ({ data, signature, jwk }) => {
  const publicKey = await crypto.subtle.importKey('jwk', jwk, { name: 'ECDSA', namedCurve: 'P-256' }, false, [
    'verify',
  ])
  return crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, publicKey, signature, data)
}
```

## Entity statements

### Creating an entity configuration

```typescript
import { createEntityConfiguration } from '@owf/openid-federation'

const now = Math.floor(Date.now() / 1000)

// Serve it at `${entityId}/.well-known/openid-federation` as `application/entity-statement+jwt`
const entityConfigurationJwt = await createEntityConfiguration({
  header: { kid: 'federation-key', typ: 'entity-statement+jwt', alg: 'ES256' },
  claims: {
    iss: 'https://rp.example.org',
    sub: 'https://rp.example.org',
    iat: now,
    exp: now + 24 * 60 * 60,
    jwks: { keys: [federationPublicJwk] },
    authority_hints: ['https://intermediate.example.org'],
    metadata: {
      openid_relying_party: { client_name: 'Example RP', redirect_uris: ['https://rp.example.org/callback'] },
    },
  },
  signJwtCallback,
})
```

`iat`, `exp` and the other date claims are NumericDate values (seconds since the epoch). Parsed claims return them as
`Date` objects.

### Creating a subordinate statement

```typescript
import { createEntityStatement } from '@owf/openid-federation'

// Serve it from the `federation_fetch_endpoint` of the issuer for `?sub=https://rp.example.org`
const subordinateStatementJwt = await createEntityStatement({
  jwk: intermediateFederationJwk, // the issuer's key, used for the `kid` in the header
  claims: {
    iss: 'https://intermediate.example.org',
    sub: 'https://rp.example.org',
    iat: now,
    exp: now + 24 * 60 * 60,
    jwks: { keys: [federationPublicJwk] }, // the subject's federation keys
    metadata_policy: {
      openid_relying_party: { grant_types: { subset_of: ['authorization_code', 'refresh_token'] } },
    },
  },
  signJwtCallback,
})
```

### Fetching

```typescript
import { fetchEntityConfiguration, fetchEntityStatement } from '@owf/openid-federation'

const entityConfiguration = await fetchEntityConfiguration({
  entityId: 'https://intermediate.example.org',
  verifyJwtCallback,
})

const subordinateStatement = await fetchEntityStatement({
  iss: 'https://intermediate.example.org',
  sub: 'https://rp.example.org',
  issEntityConfiguration: entityConfiguration,
  verifyJwtCallback,
})
```

`fetchEntityConfiguration` checks that the entity configuration is about the requested entity and signed with one of its
own keys. `fetchEntityStatement` checks the `iss` and `sub` of the statement and its signature with the issuer's keys.

## Resolving trust chains

```typescript
import { resolveTrustChains } from '@owf/openid-federation'

const trustChains = await resolveTrustChains({
  entityId: 'https://rp.example.org',
  trustAnchors: [{ entityId: 'https://ta.example.org', jwks: trustAnchorJwks }],
  verifyJwtCallback,
  fetchCallback, // optional, defaults to the global fetch
})

for (const { resolvedLeafMetadata, jwtChain, expiresAt } of trustChains) {
  resolvedLeafMetadata?.openid_relying_party // metadata after the metadata policies of the chain are applied
  jwtChain // leaf entity configuration, subordinate statements and trust anchor entity configuration as JWTs
  expiresAt // earliest `exp` of the chain
}
```

The resolver follows the `authority_hints` of the leaf to the trust anchors and validates every path as described in
[Section 10](https://openid.net/specs/openid-federation-1_0.html#section-10):

- the signature of each statement with a key the next statement lists for its issuer, and of the last one with the
  trust anchor's keys. Pass the trust anchor's `jwks`, obtained out of band, to check its entity configuration as well.
- `iat`, `exp` (`currentDate`, `clockSkewSeconds`) and `crit` (`understoodCriticalClaims`) of every statement.
- the claims each kind of statement may contain (Section 3.2).
- the `max_path_length` and `allowed_entity_types` constraints. Chains with `naming_constraints` are rejected, as they
  are not evaluated.
- the metadata policies (Section 6), which are merged from the trust anchor down and applied to the leaf's metadata.

Trust marks are not verified.

The entity configurations name the URLs that are fetched. Pass a `fetchCallback` that applies your outbound request
policy (allowed hosts, timeouts, response size). `maxDepth` (default 8), `maxRequests` (default 64) and
`maxAuthorityHints` (default 10) bound the resolution.

`resolveTrustChainsWithFailures` also returns why each path was rejected:

```typescript
import { resolveTrustChainsWithFailures } from '@owf/openid-federation'

const { trustChains, failures } = await resolveTrustChainsWithFailures(options)
for (const { entityIds, reason } of failures) {
  console.log(`${entityIds.join(' -> ')}: ${reason}`)
}
```

## Metadata policies

The policy functions the resolver uses are exported as well:

```typescript
import { applyMetadataPolicyToMetadata, combineMetadataPolicies } from '@owf/openid-federation'

// The subordinate statements of the chain, leaf side first
const { mergedPolicy } = combineMetadataPolicies({ statements })
const { resolvedLeafMetadata } = applyMetadataPolicyToMetadata({ leafMetadata, policyMetadata: mergedPolicy })
```

The standard operators `value`, `add`, `default`, `one_of`, `subset_of`, `superset_of` and `essential` are supported.
Merging operators that conflict throws a `PolicyOperatorMergeError`, applying a policy the metadata does not satisfy
throws a `PolicyValidationError`.

## Platform Support

This library is **platform agnostic** and works in:

- ✅ Node.js (>=20)
- ✅ Browsers (modern browsers with ES2020 support)
- ✅ React Native

`TextEncoder`, `TextDecoder` and, unless a `fetchCallback` is passed, `fetch` must be available.

## Contributing

See the [Contributing Guide](https://github.com/openwallet-foundation-labs/identity-common-ts/blob/main/CONTRIBUTING.md) for details on how to contribute to this project.

## License

This project is licensed under the [Apache License Version 2.0](https://github.com/openwallet-foundation-labs/identity-common-ts/blob/main/LICENSE) (Apache-2.0).

## Credits

This library was initially created by [Animo](https://animo.id) as part of the
[SPRIN-D EUDI Wallet Prototypes Funke](https://www.sprind.org/en/impulses/challenges/eudi-wallet-prototypes).
