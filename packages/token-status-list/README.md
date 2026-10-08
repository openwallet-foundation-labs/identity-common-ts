# @owf/token-status-list

Implementation of [Token Status List (draft-ietf-oauth-status-list)](https://datatracker.ietf.org/doc/draft-ietf-oauth-status-list/)
with core bitstring handling, JWT transport, and CWT/CBOR transport — all in one package.

## Features

- **Core StatusList**: Variable bit-width (1/2/4/8-bit) status entries with deflate compression
- **Random index assignment**: Deterministic, non-repeating index allocation from a private seed
- **JWT transport**: Sign, decode and verify Status List Tokens in JWT format, on top of `@owf/jose`
- **CWT transport**: Sign, decode and verify Status List Tokens in CWT format, on top of `@owf/cose`
- **Referenced Token support**: Read the status list entry of a JWT referenced token, and the
  `StatusListInfo` an ISO/IEC 18013-5 MSO refers to its status list with

## Installation

```bash
npm install @owf/token-status-list
```

## Usage

### Core — create and query a status list

```typescript
import { StatusList, StatusType } from '@owf/token-status-list'

// Create a list of 100 000 entries at 1 bit each
const list = new StatusList(new Array(100_000).fill(StatusType.Valid), 1)

// Mark some entries
list.setStatus(42, StatusType.Invalid)
list.setStatus(99, StatusType.Invalid)

// Query a status
list.getStatus(42) // 1 (Invalid)
list.getStatus(0)  // 0 (Valid)

// Compress / decompress for transport
const compressed = list.compressStatusListToBytes()
const restored = StatusList.decompressStatusListFromBytes(compressed, 1)
```

### Randomly assign status-list indices

Two allocators assign each index of a status list exactly once, in a random order that can't be
predicted without a secret. `StatusListIndexAllocator` suits lists under 1,000,000 indices and
`FeistelStatusListIndexAllocator` lists of 1,000,000 or more. See [Choosing an allocator](#choosing-an-allocator).

Persist the allocator state and advance it atomically when issuing tokens. Database transactions are
the caller's responsibility.

#### `StatusListIndexAllocator`

Shuffles all indices with a private seed. The seed is part of the state, so keep the state secret.

```typescript
import { hasher } from '@owf/crypto'
import { StatusListIndexAllocator, createStatusListIndexAllocator } from '@owf/token-status-list'

// The package never touches a global Web Crypto implementation: pass the
// hasher that expands the seed. It must compute SHA-256 for the permutation to
// be reproducible across restarts.
const ctx = { hasher }

// Once per status list: a random seed
const seed = crypto.getRandomValues(new Uint8Array(32))

const allocator = await createStatusListIndexAllocator({ length: 100_000, seed }, ctx)
const index = allocator.next()
const state = allocator.getState() // { length, position, seed }: persist it, and keep it secret

// Resume later. This shuffles the whole list again.
const resumed = await StatusListIndexAllocator.create(state, ctx)
```

#### `FeistelStatusListIndexAllocator`

Encrypts each position with FF1, NIST's Feistel-based format-preserving encryption (SP 800-38G),
under a private AES key. The key isn't part of the state. The list needs at least 1,000,000 indices,
and a power of two is fastest (see below).

```typescript
import { getAesBlockEncrypter } from '@owf/crypto'
import { FeistelStatusListIndexAllocator, createFeistelStatusListIndexAllocator } from '@owf/token-status-list'

// Once: a random AES key, which can serve several lists
const key = crypto.getRandomValues(new Uint8Array(32))
const ctx = { encryptBlock: await getAesBlockEncrypter(key) }

// Per status list: a unique tweak, such as its URI
const tweak = new TextEncoder().encode('https://example.com/statuslists/1')
const allocator = createFeistelStatusListIndexAllocator({ length: 2 ** 20, tweak }, ctx)
const index = await allocator.next()
const state = allocator.getState() // { length, position, tweak }: persist it with a reference to the key

// Resume later. Nothing is computed up front.
const resumed = FeistelStatusListIndexAllocator.create(state, ctx)
```

One key can serve several lists when each list has its own tweak. The tweak:

- Must be unique among the lists that share the key. Lists with the same tweak, or without one, get
  mostly the same order, even when their lengths differ. FF1 encrypts within the smallest power of
  two that holds the list, so under one key and tweak, lists of 1,000,000 and 2^20 indices assign the
  same index at about 95% of positions.
- Must stay the same for the life of the list. Another tweak gives another order, and new indices
  would collide with ones already handed out. `getState()` includes it.
- Doesn't have to be secret, so a public facing ID for the status list works, but see the note on size below.

Without a tweak, use a new key for each list.

A tweak of up to 13 bytes is free. Each further 16 bytes adds one AES call to every `next()`, which
makes 11 calls without a tweak. A 33-byte URI makes 13, about 20% slower. A short unique ID, such as
a database ID, keeps it free.

Choose a power of two for the length, such as 2^20 (1,048,576). A position that FF1 maps outside the
list is encrypted again until it lands inside. With a power of two that never happens, and each
`next()` encrypts once. Just above a power of two, such as 2^20 + 1, half the values fall outside and
`next()` takes twice as long on average.

The key needs the same care as the seed of `StatusListIndexAllocator`. Whoever has it can compute the
position behind every index, so they learn the order credentials were issued in, as if indices were
assigned sequentially. They can't change or forge statuses. An HSM or key management service is
therefore optional.

`encryptBlock` encrypts one 16-byte block with AES (AES-ECB without padding). Instead of
`@owf/crypto`, any AES implementation that can encrypt a raw block works: AES-ECB, or AES-CBC with a
zero IV, keeping the first 16 bytes. HSMs do over PKCS#11, and so do Google Cloud KMS (raw symmetric
encryption) and Azure Managed HSM. AWS KMS doesn't. Each AES call of `next()` is a round trip to a
remote key, made in sequence.

If `encryptBlock` throws, `next()` rejects and that position is skipped: its index is never handed
out. An index is never handed out twice.

#### Choosing an allocator

| | `StatusListIndexAllocator` | `FeistelStatusListIndexAllocator` |
| --- | --- | --- |
| How it works | Shuffles all indices (Fisher-Yates) | Encrypts each position with FF1 |
| List length | 1 to 2^32 - 1 | 1,000,000 to 2^32 - 1, ideally a power of two |
| Generate once per list | A random seed | A unique tweak, or a random AES key |
| Persist to resume | `getState()`, secret as it holds the seed | `getState()`, and a reference to the key |
| Initialize (create or resume), 1,000,000 indices | 243 ms | under 1 µs |
| Initialize (create or resume), 2^24 indices | 5.3 s | under 1 µs |
| `next()` | Synchronous, a lookup | Asynchronous, 20 µs with synchronous AES, 170 µs with Web Crypto |
| Memory, 1,000,000 indices | 4 MB | none |
| Security | Rests on SHA-256 | Rests on AES and FF1, see below |
| Best for | Lists under 1,000,000 indices | Lists of 1,000,000 indices or more |

Measured in Node.js 24 on an Apple M4 Pro, with `@owf/crypto` and `node:crypto` as the synchronous
AES. Each `next()` makes about 11 AES calls, and Web Crypto adds a few microseconds of asynchronous
overhead to each one. `StatusListIndexAllocator` shuffles the whole list every time it is created,
including when it resumes from a state.

Someone who links credentials to the order they were issued in, for example through their issuance
time, learns which index belongs to which position. The question is whether those pairs help them
predict other indices. With `StatusListIndexAllocator` they don't, unless they can predict SHA-256
output for the private seed. With `FeistelStatusListIndexAllocator` they don't, unless they can
break FF1. Attacks on Feistel networks get easier as the number of possible values shrinks, and NIST
notes they become feasible on small domains. NIST therefore requires FF1 to encrypt within at least
1,000,000 values. This allocator requires the list itself to hold that many, which is slightly
stricter. At that size NIST estimates an attack needs at least 2^77 known pairs to recover a single
value, while a status list holds at most 2^32.

### JWT transport — issue and verify a Status List Token

The `signer`, `signJwsCallback` and `verifyJwsCallback` are the ones of `@owf/jose`.

```typescript
import { StatusList, StatusType, signStatusListJwt, verifyStatusListJwt } from '@owf/token-status-list'

const list = new StatusList(new Array(100_000).fill(StatusType.Valid), 1)
list.setStatus(42, StatusType.Invalid)

// Creates, validates and signs the header and payload. `typ` defaults to `statuslist+jwt`, `alg` is
// taken from the signer, and the header identifies the signer. Use `createHeaderAndPayload` to only
// create the header and payload.
const { jwt } = await signStatusListJwt({
  statusList: list,
  payload: { iss: 'https://issuer.example', sub: 'https://issuer.example/statuslists/1', iat: Math.floor(Date.now() / 1000) },
  signer,
  signJwsCallback,
})

// Verify the signature, the claims (`sub` must equal the uri) and, when `idx` is given, that the
// status at that index is valid
const { payload: verifiedPayload, statusList } = await verifyStatusListJwt({
  jwt,
  uri: 'https://issuer.example/statuslists/1',
  idx: 7,
  verifyJwsCallback,
})
statusList.getStatus(42) // 1
```

`signStatusListJwt` puts the header parameters that identify the signer in the header, as
`jwsHeaderFromSigner` of `@owf/jose` gives them: `x5c` for an `x5c` signer, `jwk` for a `jwk` signer,
the DID URL as `kid` for a `did` signer, `kid` and `trust_chain` for a `federation` signer, and the
`kid` of a `custom` signer that has one. A verifier establishes the signer from them, as
`verifyStatusListJwt` does by default. The `header` you pass can repeat them and add others, such as a
`kid` next to an `x5c`. A header that contradicts the signer is rejected with a
`JoseInvalidArgumentError` instead of being signed: a `kid`, `x5c`, `trust_chain` or `jwk` with another
value than the signer's, and, unless the signer is a `custom` one, a parameter that identifies the
signer by another method, such as a `jwk` next to the `x5c` of an `x5c` signer. A `kid` that is a DID
URL identifies a `did` signer, and so does a fragment such as `#key-1` when `iss` is a DID, as a
verifier resolves it against `iss`. `createHeaderAndPayload` does not know the signer, so spread
`jwsHeaderFromSigner(signer)` into the header you give it.

`createHeaderAndPayload` and `signStatusListJwt` reject a `typ` other than `statuslist+jwt` (or
`application/statuslist+jwt`) with a `JoseValidationError`, rather than overwriting it. That includes
an empty `typ`, which earlier versions of this README passed: leave `typ` out instead.

`verifyStatusListJwt` decompresses `lst` only once the signature and the claims have verified: a few
kilobytes of it can inflate to a list of any size, so it is not decompressed while it is not yet known
to be the issuer's.

Use `decodeStatusListJwt(jwt)` to read the header and payload without verifying the signature, for
example to select the key before calling `verifyStatusListJwt`. Its `statusList` is decompressed when it
is first read, so read the `statusList` that `verifyStatusListJwt` returns instead. When it is given a
decoded token, `verifyStatusListJwt` decodes its compact serialization again, so what it verifies and
returns is what the signature covers.

Both reject a token whose `typ` header is missing or is not `statuslist+jwt` (`application/statuslist+jwt`
is accepted too, as RFC 7515 requires), before its signature is verified.

### JWT transport — read a referenced token's status entry

```typescript
import { decodeJwt } from '@owf/jose'
import { zJwtWithStatusListPayload } from '@owf/token-status-list'

const { payload } = decodeJwt({ jwt: referencedTokenJwt, payloadSchema: zJwtWithStatusListPayload })
// payload.status.status_list.idx  — index into the status list
// payload.status.status_list.uri  — URI of the Status List Token
```

### CWT transport — issue and verify a Status List Token

The `signingKey` and `issuerKey` are `CoseKey`s, and `sign1Context` holds the `sign` and `verify`
callbacks of `@owf/cose`.

```typescript
import { SignatureAlgorithm } from '@owf/cose'
import { StatusList, StatusListCwt, StatusType } from '@owf/token-status-list'

const list = new StatusList(new Array(100_000).fill(StatusType.Valid), 1)
list.setStatus(42, StatusType.Invalid)

// `typ` (16) is set to `application/statuslist+cwt`, and `iat` defaults to now
const cwt = new StatusListCwt({
  payload: { subject: 'https://issuer.example/statuslists/1', statusList: list, timeToLive: 3600 },
})
const token = await cwt.signAndEncode({ signingKey, algorithm: SignatureAlgorithm.ES256 }, sign1Context)

// Verify the signature, the claims (`sub` must equal the uri) and, when `idx` is given, that the
// status at that index is valid
const decoded = StatusListCwt.fromToken(token)
await decoded.verify({ key: issuerKey, uri: 'https://issuer.example/statuslists/1', idx: 7 }, { sign1: sign1Context })
decoded.payload.statusList.getStatus(42) // 1
```

The status list of a decoded token is decompressed when `payload.statusList` is first read, which
`verify` does only once the signature and the claims have verified.

### CWT transport — the status list entry of an mdoc

ISO/IEC 18013-5 second edition refers to the status list entry of an mdoc from its Mobile Security
Object with a `StatusListInfo`:

```typescript
import { StatusListInfo } from '@owf/token-status-list'

const info = StatusListInfo.create({ uri: 'https://issuer.example/statuslists/1', idx: 42 })
const decoded = StatusListInfo.decode(info.encode())
// decoded.idx === 42, decoded.uri === 'https://issuer.example/statuslists/1'
```

## Known limitation

The compressed status-list format stores statuses in whole bytes, but does not
store the original number of status entries. For example, three 1-bit entries
are encoded in one byte, so decompressing that byte produces eight byte-aligned
entries. The first three status values are preserved, but the original list
length cannot be reconstructed from `bits` and `lst` alone.

This is allowed by the specification: Section 4.1 permits the byte array to be
the size of the number of Referenced Tokens multiplied by `bits` divided by 8,
or greater. Section 13.4 recommends byte-aligned list sizes but does not require
them. Callers that need the original logical length must preserve it separately.

## API

### Core

| Export | Description |
|--------|-------------|
| `StatusList` | Main class — construct, get/set status, compress/decompress |
| `createStatusListIndexAllocator` | Create a seeded allocator that returns each status-list index once |
| `StatusListIndexAllocator` | Allocator class with `next()`, `remaining()`, and `getState()` |
| `StatusListIndexAllocatorState` | Restorable allocator state type |
| `createFeistelStatusListIndexAllocator` | Create an FF1 allocator for lists of 1,000,000 indices or more |
| `FeistelStatusListIndexAllocator` | FF1 allocator class with async `next()`, `remaining()`, and `getState()` |
| `FeistelStatusListIndexAllocatorState` | Restorable FF1 allocator state type |
| `EncryptBlock` | Type of the `encryptBlock` callback: AES on one 16-byte block |
| `StatusListError` | Error class thrown by status-list operations |
| `StatusType` | Enum of the status values: `Valid`, `Invalid`, `Suspended`, … |
| `StatusListMediaTypes` | MIME types for JWT and CWT status list tokens |
| `BitsPerStatus` | Type: `1 \| 2 \| 4 \| 8` |
| `StatusListEntry` | Type: `{ idx: number; uri: string }` |
| `fetchStatusList` | Fetch a Status List Token in JWT or CWT format by its uri |

### JWT Transport

| Export | Description |
|--------|-------------|
| `signStatusListJwt` | Create, validate and sign a Status List Token carrying a `StatusList`, with a header that identifies the signer |
| `createHeaderAndPayload` | Build and validate a JWT header + payload from a `StatusList` |
| `decodeStatusListJwt` | Decode a Status List Token, without verifying the signature; its `StatusList` is decompressed when read |
| `verifyStatusListJwt` | Verify the signature, claims and optionally the status at an index |
| `verifyStatusListJwtClaims` | Verify only the claims of a decoded Status List Token |
| `zStatusListJwtHeader` / `zStatusListJwtPayload` | Schemas for a Status List Token |
| `zJwtWithStatusListPayload` / `zStatusListEntry` | Schemas for the payload of a referenced token and its status list entry |
| `JWT_STATUS_LIST_TYPE` | `"statuslist+jwt"` |
| `JwtClaimNames` | Claim name constants |
| `JoseError`, `JoseParseError`, … | The `@owf/jose` errors signing, decoding and verifying a Status List Token in JWT format raise |

### CWT Transport

| Export | Description |
|--------|-------------|
| `StatusListCwt` | Create, sign, decode (`fromToken`) and verify a Status List Token in CWT format |
| `StatusListCwtPayload` | The claims of a Status List Token in CWT format, and `verifyClaims` |
| `StatusListCwtProtectedHeaders` | The protected headers, which require `typ` to be `application/statuslist+cwt` |
| `StatusListCbor` | The `status_list` claim, with its `StatusList` decompressed when read |
| `StatusListCwtClaimKey` | The claim keys of `ttl` (65534) and `status_list` (65533) |
| `StatusListInfo` | The status list entry an ISO/IEC 18013-5 MSO refers to |
