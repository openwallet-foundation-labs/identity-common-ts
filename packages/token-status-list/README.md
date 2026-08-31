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

Use a private, persisted seed to assign each index exactly once in a deterministic random order:

```typescript
import { hasher } from '@owf/crypto'
import { StatusListIndexAllocator, createStatusListIndexAllocator } from '@owf/token-status-list'

// The package never touches a global Web Crypto implementation: pass the
// hasher that expands the seed. It must compute SHA-256 for the permutation to
// be reproducible across restarts.
const ctx = { hasher }

const allocator = await createStatusListIndexAllocator({ length: 1_000_000, seed }, ctx)
const index = allocator.next()
const state = allocator.getState() // persist with the allocation counter

// Resume later — the persisted state is accepted as-is
const resumed = await StatusListIndexAllocator.create(state, ctx)
```

The seed must remain private to prevent predicting future assignments. Persist the allocator state
and advance it atomically when issuing tokens; database transactions are the caller's responsibility.

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
