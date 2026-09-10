# @owf/token-status-list

## 0.4.0

### Minor Changes

- c55b5d0: **Breaking:** stop reaching for `globalThis.crypto`. Hashing now comes from a caller-supplied,
  pluggable implementation, so consumers on runtimes without a global Web Crypto API — and consumers
  that must route crypto through a reviewed or policy-constrained engine — are no longer forced to
  patch the global.
  
  - `@owf/token-status-list`: `createStatusListIndexAllocator` and `StatusListIndexAllocator.create` take
    `(options, ctx)` instead of positional arguments, where `options` is `{ length, seed, position? }` and
    `ctx` is `{ hasher }`. The hasher must compute SHA-256 for the permutation to stay reproducible.
    Persisted allocator state can be passed straight through: `StatusListIndexAllocator.create(state, ctx)`.
  - `@owf/eudi-jades`: `Token.getHash` takes the hasher as its first argument —
    `getHash(hasher, algorithm?)`, e.g. `token.getHash(hasher)` with `hasher` from `@owf/crypto`.
- 0cd489f: add random index allocator
- 1aa5cb6: Verify the claims of a Status List Token, and add clock skew.
  
  `StatusListCwt(Payload).verifyClaims` verify the Token Status List requirements on top of the generic CWT claim verification: `sub` and `iat` are REQUIRED, and `sub` has to match the URI the token was referenced by. `StatusListCwt(Payload).verifyStatus(idx)` checks that the status at an index is valid.
  
  `StatusListCwt.verify` verifies a status list token completely:
  
  - signature or authentication tag
  - claims
  - the status of a specific index if `idx` is given.
  
  ```ts
  await statusListCwt.verify({ key, uri, idx }, { sign1: sign1Context })
  ```
  
  Breaking change: `StatusListCwt.verifyStatus` does not verify the claims anymore, this is handled by `verifyClaims` or the general `verify` method.
  
  Both serializations accept `skewSeconds` (default 30) as the clock tolerance for `exp`, `nbf` and `iat`. The CWT one takes `requiredClaims` for profiles that make a further claim mandatory (e.g. `exp` for ISO/IEC 18013-5 second edition), the JWT one `requireExpirationTime`. A `nbf` in the future is now rejected.
  
  Fixes: the JWT `verifyStatus` read the subject from a `subject` claim, which a conformant Status List Token never carries (the registered claim is `sub`)
- 46a42a3: Typed CWT payload and headers, extensible per CWT type.
  
  A CWT type is expressed by the structures it is made of, each validating itself through its own `encodingSchema`. `Cwt` holds no schemas and no per-type statics.
  
  - Payload: a `CwtPayload` subclass, schema from `extendCwtPayloadClaims`. The registered RFC 8392 claims are typed accessors (`issuer`, `subject`, `audience`, `expirationTime`, `notBefore`, `issuedAt`, `cwtId`); `getClaim` reads any claim, `unknown` if undeclared. A claim redeclared as required is no longer optional on the inherited accessor.
  - Headers: a `ProtectedHeaders` / `UnprotectedHeaders` subclass, schema from `extendCoseHeaderClaims` (wrapped in `protectedHeadersSchema` for the protected bucket, which is carried in a bstr). Each bucket validates only against its own schema, so a parameter that must be integrity protected cannot be satisfied by an unprotected copy.
  - Decoding names the classes, and types the result from them:
  
  ```ts
  const cwt = Cwt.fromToken(token, {
    payload: StatusListCwtPayload,
    protectedHeaders: StatusListCwtProtectedHeaders,
  })
  ```
  
  A CWT type that carries extra logic subclasses `Cwt` and overrides `fromToken` to supply them, so callers do not repeat the classes.
  
  `typ` (16, RFC 9596) is now `RegisteredCwtHeaderClaimKey.Typ`, readable as `Cwt.typ`. `typ` and `algorithm` read the protected headers only; `keyId` falls back to unprotected.
  
  Breaking changes:
  
  - `CwtOptions` is no longer `Sign1Options | Mac0Options`. `Cwt` takes a `CwtPayload` as `payload` plus `signatureOrTag`; the signed bytes are `payloadBytes`.
  - `Cwt.payload` is a `CwtPayload`, not `Uint8Array | null`. A detached payload throws `CwtDetachedPayloadError` at `fromToken`, an invalid claims set `CwtPayloadDecodeError`.
  - `Cwt.fromToken` requires the structures as a second argument, e.g. `Cwt.fromToken(token, { payload: CwtPayload })`.
  - `ProtectedHeaders` / `UnprotectedHeaders` are typed by their header map, so `decodedStructure` reflects the profile's map.
  - `StatusListCwtPayload.getCustomClaim` is replaced by `getClaim`, which infers the value type instead of taking it as a type argument.
  - `StatusListCwtHeaderKey` is removed; use `RegisteredCwtHeaderClaimKey.Typ`.
  - `StatusListCwt` requires protected `typ` = `application/statuslist+cwt`, via the new `StatusListCwtProtectedHeaders`. Still defaulted when absent, but a token with a different `typ` is now rejected.

### Patch Changes

- e40f6a2: fix bug for payload verification
- 5934a14: Add `extractMediaType` and `isMediaType` to `@owf/identity-common` for comparing `Content-Type` header values against expected media types, ignoring casing and parameters.
  
  `fetchStatusList` now uses `isMediaType` instead of an exact string match on the `Content-Type` response header, so a status list served as e.g. `application/statuslist+jwt; charset=utf-8` or `Application/StatusList+CWT` is no longer rejected.
- 019050d: Keep the `lst` claim of a status list compressed in `StatusListCbor`, so a decoded status list re-encodes to the bytes it was decoded from. DEFLATE has no canonical form, so inflating and deflating again is not guaranteed to reproduce the issuer's stream.
  
  This also fixes two related bugs in the same structure:
  
  - `aggregation_uri` was effectively required, so a status list that omits the claim could not be decoded at all.
  - `aggregation_uri` was written with an explicit `undefined` value when no aggregation uri was set, instead of the key being omitted. Status lists encoding the claim that way (including ones this library issued up to 0.3.1) are now rejected on decode.
- 46a42a3: fix: use .arrayBuffer on CWT Token Status List response, as react native does not support .blob()
- Updated dependencies [46a42a3]
- Updated dependencies [b7e7f15]
- Updated dependencies [46a42a3]
- Updated dependencies [5934a14]
- Updated dependencies [46a42a3]
- Updated dependencies [46a42a3]
- Updated dependencies [8c4c570]
  - @owf/cose@0.4.0
  - @owf/identity-common@0.4.0

## 0.3.2

### Patch Changes

- @owf/cose@0.3.2
- @owf/identity-common@0.3.2

## 0.3.1

### Patch Changes

- @owf/cose@0.3.1
- @owf/identity-common@0.3.1

## 0.3.0

### Minor Changes

- eff25c4: remove export from dependencies
- dad635c: refactor: only allow CoseKey as return value for getPublicKey in x509 context
- dad635c: refactor: only allow CosKey for sign1.verify

### Patch Changes

- 353df0c: feat: add status list info objects for referenced status list token
- 9451711: Add a way for a CWT status list to add additional claims
- 4928369: feat: make totalStatuses public readonly in StatusList class
- Updated dependencies [4bd7eb7]
- Updated dependencies [f1f42db]
- Updated dependencies [dad635c]
- Updated dependencies [6309c48]
- Updated dependencies [353df0c]
- Updated dependencies [dad635c]
- Updated dependencies [353df0c]
- Updated dependencies [353df0c]
- Updated dependencies [353df0c]
- Updated dependencies [2b0eeaf]
  - @owf/cose@0.3.0
  - @owf/identity-common@0.3.0

## 0.2.0

### Minor Changes

- 7ef6497: Migrate reusable packages from sd-jwt-js

  - **@owf/identity-common**: Add shared types (JwtPayload, Signer, Verifier, Hasher, etc.), base64url utilities, and JWT decoding
  - **@owf/crypto**: Add Web Crypto API wrappers (ES256/384/512 key generation, signing, verification) and SHA-256/384/512 hash functions
  - **@owf/token-status-list**: Add core StatusList class with bitstring compression/decompression (1/2/4/8-bit), JWT transport layer, and CWT/CBOR transport layer for Token Status Lists (draft-ietf-oauth-status-list)

### Patch Changes

- b79d4ba: align package json for export
- f50ec6e: add lote package

  add package-specific exception classes (`CryptoException`, `LoTEException`, `IdentityCommonException`) extending a shared `IdentityException` base class in `@owf/identity-common`, replacing plain `Error` throws across all packages. Refactor `SLException` to also extend `IdentityException`.

- 293e5ec: Also include commonjs builds
- Updated dependencies [b79d4ba]
- Updated dependencies [7ef6497]
- Updated dependencies [f50ec6e]
- Updated dependencies [293e5ec]
  - @owf/identity-common@0.2.0
  - @owf/cose@0.2.0

## 0.1.0

### Minor Changes

- 7ef6497: Migrate reusable packages from sd-jwt-js

  - **@owf/identity-common**: Add shared types (JwtPayload, Signer, Verifier, Hasher, etc.), base64url utilities, and JWT decoding
  - **@owf/crypto**: Add Web Crypto API wrappers (ES256/384/512 key generation, signing, verification) and SHA-256/384/512 hash functions
  - **@owf/token-status-list**: Add core StatusList class with bitstring compression/decompression (1/2/4/8-bit), JWT transport layer, and CWT/CBOR transport layer for Token Status Lists (draft-ietf-oauth-status-list)

### Patch Changes

- f50ec6e: add lote package

  add package-specific exception classes (`CryptoException`, `LoTEException`, `IdentityCommonException`) extending a shared `IdentityException` base class in `@owf/identity-common`, replacing plain `Error` throws across all packages. Refactor `SLException` to also extend `IdentityException`.

- Updated dependencies [7ef6497]
- Updated dependencies [f50ec6e]
  - @owf/identity-common@0.1.0
