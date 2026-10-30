# @owf/token-status-list

Implementation of [Token Status List (draft-ietf-oauth-status-list)](https://datatracker.ietf.org/doc/draft-ietf-oauth-status-list/)
with core bitstring handling, JWT transport, and CWT/CBOR transport — all in one package.

## Features

- **Core StatusList**: Variable bit-width (1/2/4/8-bit) status entries with deflate compression
- **Random index assignment**: Deterministic, non-repeating index allocation from a private seed
- **JWT transport**: Create and decode Status List Tokens in JWT format
- **CWT transport**: Create and decode Status List Tokens in CWT/CBOR format
- **Referenced Token support**: Extract status claims from both JWT and CWT referenced tokens
- **COSE algorithm constants**: Standard IANA COSE algorithm identifiers

## Installation

```bash
npm install @owf/token-status-list
```

## Usage

### Core — create and query a status list

```typescript
import { StatusList, StatusTypes } from '@owf/token-status-list'

// Create a list of 100 000 entries at 1 bit each
const list = new StatusList(new Array(100_000).fill(0), 1)

// Mark some entries
list.setStatus(42, StatusTypes.INVALID)
list.setStatus(99, StatusTypes.INVALID)

// Query a status
list.getStatus(42) // 1 (INVALID)
list.getStatus(0)  // 0 (VALID)

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

### JWT transport — issue and read a Status List Token

```typescript
import { StatusList, createHeaderAndPayload, getListFromStatusListJWT } from '@owf/token-status-list'

const list = new StatusList(new Array(100_000).fill(0), 1)
list.setStatus(42, 1)

// Build header + payload (sign with your own JOSE library)
const { header, payload } = createHeaderAndPayload(
  list,
  { iss: 'https://issuer.example', sub: 'https://issuer.example/statuslists/1', iat: Math.floor(Date.now() / 1000) },
  { alg: 'ES256', typ: '' },
)

// Later — decode the list back from a JWT string
const decoded = getListFromStatusListJWT(jwt)
decoded.getStatus(42) // 1
```

### JWT transport — read a referenced token's status entry

```typescript
import { getStatusListFromJWT } from '@owf/token-status-list'

const entry = getStatusListFromJWT(referencedTokenJWT)
// entry.idx  — index into the status list
// entry.uri  — URI of the Status List Token
```

### CWT transport — issue and read a Status List Token

```typescript
import {
  StatusList,
  COSEAlgorithms,
  createStatusListCWTPayload,
  createStatusListCWTHeader,
  encodeCWTPayload,
  decodeCWTPayload,
} from '@owf/token-status-list'

const list = new StatusList(new Array(100_000).fill(0), 1)
list.setStatus(42, 1)

// Build CWT claims and header (sign with your own COSE library)
const payload = createStatusListCWTPayload(list, 'https://issuer.example/statuslists/1', Math.floor(Date.now() / 1000))
const header = createStatusListCWTHeader(COSEAlgorithms.ES256, 'key-id-1')

// Encode to CBOR
const cborPayload = encodeCWTPayload(list, 'https://issuer.example/statuslists/1', Math.floor(Date.now() / 1000))

// Decode
const { subject, issuedAt, statusList } = decodeCWTPayload(cborPayload)
statusList.getStatus(42) // 1
```

### CWT transport — referenced token status claim

```typescript
import { createCWTStatusClaim, encodeCWTStatusClaim, decodeCWTStatusClaim } from '@owf/token-status-list'

// Create
const claim = createCWTStatusClaim(42, 'https://issuer.example/statuslists/1')

// Encode/decode via CBOR
const encoded = encodeCWTStatusClaim(42, 'https://issuer.example/statuslists/1')
const decoded = decodeCWTStatusClaim(encoded)
// decoded.idx === 42, decoded.uri === '...'
```

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
| `SLException` | Error class thrown by status-list operations |
| `StatusTypes` | Constants: `VALID`, `INVALID`, `SUSPENDED`, etc. |
| `MediaTypes` | MIME types for JWT and CWT status list tokens |
| `BitsPerStatus` | Type: `1 \| 2 \| 4 \| 8` |
| `StatusListEntry` | Type: `{ idx: number; uri: string }` |

### JWT Transport

| Export | Description |
|--------|-------------|
| `createHeaderAndPayload` | Build JWT header + payload from a `StatusList` |
| `getListFromStatusListJWT` | Decode a `StatusList` from a JWT string |
| `getStatusListFromJWT` | Extract `StatusListEntry` from a referenced token JWT |
| `JWT_STATUS_LIST_TYPE` | `"statuslist+jwt"` |
| `JWTClaimNames` | Claim name constants |

### CWT Transport

| Export | Description |
|--------|-------------|
| `createStatusListCWTPayload` | Build CWT claims from a `StatusList` |
| `createStatusListCWTHeader` | Build COSE protected header |
| `encodeCWTPayload` / `decodeCWTPayload` | CBOR encode/decode full payload |
| `encodeStatusListToCBOR` / `decodeStatusListFromCBOR` | CBOR encode/decode the status list only |
| `createCWTStatusClaim` | Build a referenced-token status claim object |
| `encodeCWTStatusClaim` / `decodeCWTStatusClaim` | CBOR encode/decode a status claim |
| `getListFromStatusListCWT` | Extract `StatusList` from CWT payload bytes |
| `getStatusListFromCWT` | Extract `StatusListEntry` from CWT payload bytes |
| `COSEAlgorithms` | IANA COSE algorithm identifiers (ES256, ES384, EdDSA, …) |
| `CWT_STATUS_LIST_TYPE` | `"application/statuslist+cwt"` |
| `CWTClaimKeys` / `CWTStatusListKeys` / `CWTStatusListInfoKeys` / `COSEHeaderKeys` | Numeric/string key constants |
