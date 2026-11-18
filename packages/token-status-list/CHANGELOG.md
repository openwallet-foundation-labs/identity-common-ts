# @owf/token-status-list

## 0.8.0

### Minor Changes

- 90614a9: Abbreviations and names in exports are written as words, e.g. `SdJwt` instead of `SDJwt` or `SDJWT`, and `Openid` instead of `OpenId`.
  
  **Breaking:** rename the exports as follows. The `name` of the renamed errors changes with them. Property names that the specifications define, such as `schemaURIs`, `LoTEType` and `X509SKIs`, don't change.
  
  - `@sd-jwt/core`: `SDJwt` to `SdJwt`, `SDJwtInstance` to `SdJwtInstance`, `SDJWTError` to `SdJwtError`, `SDJWTConfig` to `SdJwtConfig`, `SDJWTCompact` to `SdJwtCompact`, `KBJwt` to `KbJwt`, `KBOptions` to `KbOptions`, `FlattenJSON` to `FlattenJson`, `GeneralJSON` to `GeneralJson`, `DecodedSDJwt` to `DecodedSdJwt` and `getSDAlgAndPayload` to `getSdAlgAndPayload`. The types `kbHeader` and `kbPayload` are now `KbJwtHeader` and `KbJwtPayload`. The methods `toFlattenJSON`, `toGeneralJSON`, `SDJwt.decodeSDJwt`, `SDJwt.encodeSDJwt`, `KBJwt.verifyKB`, `KBJwt.fromKBEncode`, `Jwt.decodeJWT` and the static `DEFAULT_hashAlg` of `SDJwtInstance` and `SDJwtGeneralJSONInstance` are now `toFlattenJson`, `toGeneralJson`, `SdJwt.decodeSdJwt`, `SdJwt.encodeSdJwt`, `KbJwt.verifyKb`, `KbJwt.fromKbEncode`, `Jwt.decodeJwt` and `defaultHashAlg`.
  - `@sd-jwt/sd-jwt-vc`: `SDJwtVcInstance` to `SdJwtVcInstance`, `SDJWTVCConfig` to `SdJwtVcConfig`, `SDJWTVCStatusReference` to `SdJwtVcStatusReference` and `VCTFetcher` to `VctFetcher`.
  - `@owf/token-status-list`: `getListFromStatusListJWT` to `getListFromStatusListJwt`, `getStatusListFromJWT` to `getStatusListFromJwt`, `JWTClaimNames` to `JwtClaimNames`, `StatusListJWTPayload` to `StatusListJwtPayload`, `StatusListJWTHeaderParameters` to `StatusListJwtHeaderParameters` and `JWTwithStatusListPayload` to `JwtWithStatusListPayload`.
  - `@owf/eudi-lote`: `LoTE` to `Lote` in all exports, e.g. `validateLoTE` to `validateLote`, `createLoTE` to `createLote`, `LoTEError` to `LoteError` and `zLoTEDocument` to `zLoteDocument`. Also `JWKPublicKey` to `JwkPublicKey`, `LocalizedURI` to `LocalizedUri`, the builder method `addX509SKI` to `addX509Ski` and the profile option `requireNoPointersToOtherLoTE` to `requireNoPointersToOtherLote`. The list types are written the same way in the `LoteProfile` members and values, the `LOTE_TYPES` keys and the profile schemas, e.g. `LoteProfile.EUPIDProvidersList` to `LoteProfile.EuPidProvidersList`, `zEUPubEAAProvidersList` to `zEuPubEaaProvidersList` and `zMDLProvidersList` to `zMdlProvidersList`. The LoTEType URIs don't change.
  - `@owf/eudi-jades`: `JAdESError` to `JadesError`, `JAdESProfile` to `JadesProfile`, `CommitmentOIDs` to `CommitmentOids`, `OId` and `zOId` to `Oid` and `zOid`, `CompactJWS`, `FlattenedJWS` and `GeneralJWS` (and their `z` schemas) to `CompactJws`, `FlattenedJws` and `GeneralJws`, and the method `toFlattenedJSON` to `toFlattenedJson`.
  - `@owf/eudi-attestation-schema`: `SchemaURI` to `SchemaUri`, `SchemaURIMeta` to `SchemaUriMeta`, `SchemaURIBuilder` to `SchemaUriBuilder`, `schemaURI()` to `schemaUri()`, `zSchemaURI` to `zSchemaUri`, `AttestationLoS` to `AttestationLos`, `AttestationLoSValues` to `AttestationLosValues` and the builder method `addSchemaURI` to `addSchemaUri`.
  - `@owf/eudi-registration-certificate`: `isPSPSubEntitlement` to `isPspSubEntitlement`, `validateRegistrationCertificateJWTHeader` to `validateRegistrationCertificateJwtHeader`, and `JWT` and `CWT` to `Jwt` and `Cwt` in the header and payload types and schemas, e.g. `zRegistrationCertificateJWTHeader` to `zRegistrationCertificateJwtHeader`.
  - `@owf/eudi-tl`: `TSLType` to `TslType`.
  - `@openid4vc/utils`: `OpenId4VcBaseError` to `Openid4vcBaseError`, and `ContentType.OAuthAuthorizationRequestJwt` to `ContentType.OauthAuthorizationRequestJwt`.
  - `@openid4vc/openid4vp`: `parseOpenid4VpAuthorizationResponsePayload` to `parseOpenid4vpAuthorizationResponsePayload`, `ValidateOpenid4VpAuthorizationResponseResult` (and its `Dcql` and `Pex` variants) to `ValidateOpenid4vpAuthorizationResponseResult`, and the methods `Openid4vpVerifier.createOpenId4vpAuthorizationRequest` and `Openid4vpClient.resolveOpenId4vpAuthorizationRequest` to `createOpenid4vpAuthorizationRequest` and `resolveOpenid4vpAuthorizationRequest`.
  - `@owf/openid-federation`: `OpenId` to `Openid` in all exports, e.g. `OpenIdFederationError` to `OpenidFederationError`, `OpenIdProviderMetadata` to `OpenidProviderMetadata` and `openIdProviderEntityMetadata` to `openidProviderEntityMetadata`.
  - `@owf/cose`: `KeyOps.MACCreate` and `KeyOps.MACVerify` to `KeyOps.MacCreate` and `KeyOps.MacVerify`.
- 946d9af: BREAKING: the Status List Token JWT API is built on `@owf/jose`:
  
  | Removed | Use instead |
  | --- | --- |
  | `createHeaderAndPayload(list, payload, header)` | `signStatusListJwt({ statusList, payload, header, signer, signJwsCallback })` |
  | `getListFromStatusListJwt(jwt)` | `decodeStatusListJwt(jwt).statusList` |
  | `getStatusListFromJwt(jwt)` | `decodeJwt({ jwt, payloadSchema: zReferencedTokenJwtPayload }).payload.status.status_list` of `@owf/jose` |
  | `verifyStatus({ token, idx, uri, verifySignature })` | `verifyStatusListJwt({ jwt, idx, uri, verifyJwsCallback })` |
  | `VerifyStatusListJwtSignature` | `VerifyStatusListJwtOptions['verifyJwsCallback']` |
  | `verifyStatusListJwtHeader(header)` | `decodeStatusListJwt(jwt)` |
  | `StatusListEntry`, `JwtWithStatusListPayload` | `StatusListReference`, `ReferencedTokenJwtPayload` |
  
  The new `zStatusListJwtHeader`, `zStatusListJwtPayload`, `zReferencedTokenJwtPayload`, `zStatusClaim` and `zStatusListReference` schemas validate tokens as Token Status List draft 16 requires. `signStatusListJwt` only signs a `typ` of `statuslist+jwt`.
  
  BREAKING: `verifyStatusListJwtClaims` takes the options of `verifyJwtClaims` of `@owf/jose`: `requiredClaims: ['exp']` replaces `requireExpirationTime`, and `checkIssuedAt` replaces `checkFreshness`. Errors are the `@owf/jose` errors, re-exported here. Claims that don't verify throw a `JoseValidationError` with an issue per claim.
  
  `StatusList.getStatus` and `setStatus` throw a `StatusListError` for an index outside the list, a fraction or `NaN`, instead of a plain `Error`. A `ttl` that is not a positive number is rejected (draft 16 § 5.1 and § 5.2).
  
  BREAKING: `StatusListEntryNotValidError` is replaced by `StatusListValidationError`, with an issue code of `STATUS_LIST_VALIDATION_CODES`. Verifying the status at an `idx`, with `verifyStatusListJwt` or `verifyStatus` of a status list CWT, throws it with `status_not_valid` (`{ idx, status }`) for a status that is not Valid and `index_out_of_range` (`{ idx, totalStatuses }`) for an `idx` outside the list. `StatusList.decompressStatusListFromBytes` throws it with `invalid_status_list` for bytes that are not a compressed status list, or that inflate to more than `maxDecompressedBytes`, instead of a plain `Error`.
- 21cd668: `fetchStatusList` rejects a response larger than 16 MiB, which fits the largest list of Token Status List draft 16 Appendix B in either format, or than the `statusList` limit of its new `fetchLimits` option (see `FetchLimits` of `@owf/identity-common`). It checks the `Content-Length` header before reading the body, and stops reading a streamed body once it is larger than the maximum. Before, it read a body of any size into memory. Its `customFetcher` gets `{ type: 'statusList' }` as its third argument.
- 21cd668: A decompressed `StatusList` reads and sets each status in its decompressed bytes (Token Status List draft 16 § 4.1), instead of expanding the list into an array of numbers. Reading a list of 4 MiB at 1 bit per status took about 250 MB and 2 seconds, and now takes the 4 MiB of the list. The array is built only when `statusList` is read.
  
  The limit of a decompressed list is `maxDecompressedBytes`, 16 MiB by default, which is 2^27 statuses at 1 bit per status, or 2^24 at 8 bits. Token Status List draft 16 § 8.3 sets no maximum, so a signed list of about 1 MB can inflate to 1 GiB. Pass the option to `verifyStatusListJwt`, `decodeStatusListJwt`, `StatusList.decompressStatusListFromBytes`, `StatusListCwt.verify` and `verifyStatus`, and `StatusListCwtPayload.verifyStatus`. The new `getStatusList(options)` of `StatusListCwtPayload` and `StatusListCbor` reads the list with it.
- 5441d63: `verifyStatus` verifies the signature of the Status List Token before it reads its claims and the status, with a `verifySignature` callback (Token Status List Section 8.3), and rejects a token with a `crit` header (RFC 7515 Section 4.1.11). Before, it checked the header, the claims and the status of a token whose signature it never verified, so whoever could serve the status list, such as a cache or a network attacker on an http uri, could mark a revoked credential as valid.
  
  `StatusList.decompressStatusListFromBytes` stops inflating a list larger than `maxDecompressedBytes`, 16 MiB by default. A few KiB of compressed data could inflate to a list that exhausts the memory and CPU of whoever reads it, for example through `getListFromStatusListJwt` or a `StatusListCwt`.
  
  **Breaking:** `verifyStatus` is async and requires `verifySignature`, which gets the header, the JWS signing input and the signature, and returns whether the signature verifies with the key of a trusted status list issuer.
- 5fff735: Media types are compared with `isMediaType` and JOSE `typ` values with `isJwtTyp`, both from `@owf/identity-common`. New: `CommonMediaTypes` of `@owf/identity-common`, the media types that are not specific to one specification, and `Oauth2MediaTypes` of `@openid4vc/oauth2`, with the JAR request object media type. JARM accepts its `Content-Type` in any casing. A Key Binding JWT and a registration certificate accept their `typ` in any casing and with the `application/` prefix (RFC 7515 Section 4.1.9).
  
  **Breaking:** `isContentType` and `isResponseContentType` are removed from `@openid4vc/utils`. Replace `isContentType(contentType, value)` with `isMediaType(value, contentType)` and `isResponseContentType(contentType, response)` with `isMediaType(response.headers.get('Content-Type'), contentType)`. `MediaTypes` is renamed to `StatusListMediaTypes` in `@owf/token-status-list` and to `MdocMediaTypes` in `@owf/mdoc`. `ContentType` is removed from `@openid4vc/utils`: use `CommonMediaTypes`, and `Oauth2MediaTypes.AuthorizationRequestJwt` for `ContentType.OauthAuthorizationRequestJwt`. The `expectedContentType` of a `ZodFetcher` is a `string`.
- 04cfd04: Error classes are named `FooError` and zod schemas `zFoo` in all packages.
  
  **Breaking:** `*Exception` is renamed to `*Error`, e.g. `IdentityException` to `IdentityError`, `SDJWTException` to `SdJwtError`, `JwtTimeClaimException` to `JwtTimeClaimError`, `X509Exception` to `X509Error` and `SLException` to `StatusListError`. The `name` of the errors changes with it. Zod schemas are renamed from `FooSchema` (or `fooSchema`) to `zFoo`, e.g. `TypeMetadataFormatSchema` to `zTypeMetadataFormat`, `SchemaMetaSchema` to `zSchemaMeta`, `issuerSignedItemSchema` to `zIssuerSignedItem` and `Iso4217CurrencyCode` to `zIso4217CurrencyCode`.

### Patch Changes

- 21cd668: `StatusList.decompressStatusListFromBytes`, and through it `verifyStatusListJwt`, `decodeStatusListJwt` and a `StatusListCwt`, reject an `lst` in the gzip format or with bytes after the end of its ZLIB stream with an `invalid_status_list` issue. Token Status List draft 16 § 4.1 requires DEFLATE in the ZLIB format, but pako inflated a gzip stream as well, and ignored whatever followed the stream.
- Updated dependencies [90614a9]
- Updated dependencies [f6d2c57]
- Updated dependencies [4e50fca]
- Updated dependencies [ec2ed51]
- Updated dependencies [ec2ed51]
- Updated dependencies [90614a9]
- Updated dependencies [0f663bf]
- Updated dependencies [ebd0b4b]
- Updated dependencies [21cd668]
- Updated dependencies [ec2ed51]
- Updated dependencies [f6d2c57]
- Updated dependencies [5d665bb]
- Updated dependencies [946d9af]
- Updated dependencies [3127af9]
- Updated dependencies [ec2ed51]
- Updated dependencies [cb487f1]
- Updated dependencies [5fff735]
- Updated dependencies [04cfd04]
  - @owf/cose@0.8.0
  - @owf/identity-common@0.8.0
  - @owf/jose@0.8.0

## 0.7.0

### Patch Changes

- Updated dependencies [747a242]
- Updated dependencies [057107b]
- Updated dependencies [01b6985]
- Updated dependencies [23f227b]
  - @owf/cose@0.7.0
  - @owf/identity-common@0.7.0

## 0.6.2

### Patch Changes

- 13a53dc: Add `FeistelStatusListIndexAllocator` for status lists of 1,000,000 indices or more. It assigns each index by encrypting the position with FF1 (NIST SP 800-38G) under an AES key that stays in a caller-provided `encryptBlock` callback. With a unique `tweak` per list, such as its URI, one key can serve several lists. Creating or resuming one takes under 1 µs, against about 250 ms for `StatusListIndexAllocator` with 1,000,000 indices, and `next()` is asynchronous.
- @owf/cose@0.6.2
  - @owf/identity-common@0.6.2

## 0.6.1

### Patch Changes

- bf9b7c8: `fetchStatusList` asks for its `acceptedFormats` in order of preference. `verifyStatusListJwtHeader` now requires an `alg` header and returns the header it verified, typed with `alg` and `typ`. `verifyStatus` checks the header and claims before it reads the status list, reports an unreadable list as an `SLException`, and a status that is not Valid as the new `StatusListEntryNotValidException`, an `SLException` with `idx` and `status`.
- Updated dependencies [bf9b7c8]
  - @owf/identity-common@0.6.1
  - @owf/cose@0.6.1

## 0.6.0

### Patch Changes

- @owf/cose@0.6.0
  - @owf/identity-common@0.6.0

## 0.5.0

### Minor Changes

- b4105be: Drop the CommonJS build from all packages; only ESM is now published. All environments targeted by this library support ESM natively. This removes the dual-package hazard that caused `instanceof` checks to fail in Metro/Hermes and similar single-module-system runtimes.

### Patch Changes

- dacb544: Reject a token at its `exp` instant. `verifyStatusListJwtClaims` (and so `verifyStatus`) and `CwtPayload.verifyClaims` (and so `Cwt.verify` and `StatusListCwtPayload.verifyClaims`) accepted a token when the current time was exactly `exp` plus the skew. RFC 7519 section 4.1.4 says a token MUST NOT be accepted on or after its `exp`, and RFC 8392 gives `exp` the same meaning in a CWT. This matches `@sd-jwt/core`.
- Updated dependencies [b7002dd]
- Updated dependencies [b4105be]
- Updated dependencies [dacb544]
  - @owf/cose@0.5.0
  - @owf/identity-common@0.5.0

## 0.4.2

### Patch Changes

- f599719: Verify the `typ` header of a Status List Token in JWT format. Token Status List requires the header to be `statuslist+jwt`, and requires a relying party to check it. `application/statuslist+jwt` is accepted too, as RFC 7515 section 4.1.9 requires of a recipient.
  
  - `@owf/token-status-list`: new `verifyStatusListJwtHeader`, which `verifyStatus` now calls before the claims.
  - `@sd-jwt/sd-jwt-vc`: `verify` and `safeVerify` reject a status list token with a missing or wrong `typ` header, before its signature is verified.
- f2aaf3e: `StatusList` rejects status values that do not fit in `bitsPerStatus` bits instead of encoding them into the neighbouring entries. The constructor, `setStatus` and the encoder accept only integers from 0 to `2 ** bitsPerStatus - 1`, so for example a suspension (`2`) on a list with 1 bit per status now throws an `SLException`. Previously the constructor accepted `2 ** bitsPerStatus`, and negative or non-integer values were not checked at all.
- @owf/cose@0.4.2
  - @owf/identity-common@0.4.2

## 0.4.1

### Patch Changes

- @owf/cose@0.4.1
  - @owf/identity-common@0.4.1

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
- 65a7173: Export `verifyStatusListJwtClaims`, so the claims of a Status List Token in JWT format can be verified without also requiring the status at an index to be valid.
- 5934a14: Add `extractMediaType` and `isMediaType` to `@owf/identity-common` for comparing `Content-Type` header values against expected media types, ignoring casing and parameters.
  
  `fetchStatusList` now uses `isMediaType` instead of an exact string match on the `Content-Type` response header, so a status list served as e.g. `application/statuslist+jwt; charset=utf-8` or `Application/StatusList+CWT` is no longer rejected.
- 019050d: Keep the `lst` claim of a status list compressed in `StatusListCbor`, so a decoded status list re-encodes to the bytes it was decoded from. DEFLATE has no canonical form, so inflating and deflating again is not guaranteed to reproduce the issuer's stream.
  
  This also fixes two related bugs in the same structure:
  
  - `aggregation_uri` was effectively required, so a status list that omits the claim could not be decoded at all.
  - `aggregation_uri` was written with an explicit `undefined` value when no aggregation uri was set, instead of the key being omitted. Status lists encoding the claim that way (including ones this library issued up to 0.3.1) are now rejected on decode.
- 46a42a3: fix: use .arrayBuffer on CWT Token Status List response, as react native does not support .blob()
- 65a7173: Build all base64, base64url, UTF-8 and JSON encoding on a single implementation in `@owf/identity-common`.
  
  - `base64` and `base64url` share one codec. Decoding input with an impossible length (a single trailing character) now throws instead of returning a corrupt byte.
  - `stringToBytes` and `bytesToString` use `TextEncoder` and `TextDecoder`, which must now be available in the environment (see the React Native notes in the README). `bytesToString` and `base64urlDecode` accept `{ fatal: true }` to throw on invalid UTF-8 instead of replacing it.
  - `base64urlDecodeJson` and `decodeJwt` build on these layers.
  
  `@owf/crypto`, `@owf/eudi-jades`, `@owf/eudi-sca` and `@owf/token-status-list` use these functions instead of their own `TextEncoder`, `TextDecoder` and `JSON.parse` calls. JSON decoded from base64url (JAdES headers and `etsiU` values, transaction data, and status list token payloads) is now strict about UTF-8.
- Updated dependencies [46a42a3]
- Updated dependencies [b7e7f15]
- Updated dependencies [46a42a3]
- Updated dependencies [5934a14]
- Updated dependencies [46a42a3]
- Updated dependencies [65a7173]
- Updated dependencies [46a42a3]
- Updated dependencies [8c4c570]
- Updated dependencies [65a7173]
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
