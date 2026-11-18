# @owf/openid-federation

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
- 0f663bf: `fetchEntityConfiguration`, `fetchEntityStatement` and `resolveTrustChains` read every response within 10 MiB, or the limits of their new `fetchLimits` option (see `FetchLimits` of `@owf/identity-common`). Before, they read a response of any size. The `fetchCallback` gets `{ type: 'entityConfiguration' }` or `{ type: 'entityStatement' }`, the new `FederationFetchType`, as its third argument.
  
  **Breaking:** `fetcher.get` and `fetcher.post` take a `type`, `'entityConfiguration'` or `'entityStatement'`.
- 04cfd04: Error classes are named `FooError` and zod schemas `zFoo` in all packages.
  
  **Breaking:** `*Exception` is renamed to `*Error`, e.g. `IdentityException` to `IdentityError`, `SDJWTException` to `SdJwtError`, `JwtTimeClaimException` to `JwtTimeClaimError`, `X509Exception` to `X509Error` and `SLException` to `StatusListError`. The `name` of the errors changes with it. Zod schemas are renamed from `FooSchema` (or `fooSchema`) to `zFoo`, e.g. `TypeMetadataFormatSchema` to `zTypeMetadataFormat`, `SchemaMetaSchema` to `zSchemaMeta`, `issuerSignedItemSchema` to `zIssuerSignedItem` and `Iso4217CurrencyCode` to `zIso4217CurrencyCode`.

### Patch Changes

- ec2ed51: `MdlError` of `@owf/mdoc`, and `OpenidFederationError`, `PolicyValidationError` and `PolicyOperatorMergeError` of `@owf/openid-federation`, extend `IdentityError` instead of `Error`. The `name` of an `MdlError` is now its class, where it was `Error`.
- 755e2eb: `fetchEntityConfiguration`, `resolveTrustChains` and `resolveTrustChainsWithFailures` only fetch from https URLs: an entity id, `authority_hints` and the `federation_*_endpoint` metadata must be https URLs (OpenID Federation 1.0 Sections 1.2 and 5.1.1). These are fetched while a trust chain is resolved, before it is trusted, so an entity could make the resolver request any URL, such as an internal http endpoint.
- Updated dependencies [0f663bf]
- Updated dependencies [ebd0b4b]
- Updated dependencies [21cd668]
- Updated dependencies [ec2ed51]
- Updated dependencies [ec2ed51]
- Updated dependencies [cb487f1]
- Updated dependencies [5fff735]
- Updated dependencies [04cfd04]
  - @owf/identity-common@0.8.0

## 0.7.0

### Patch Changes

- Updated dependencies [23f227b]
  - @owf/identity-common@0.7.0

## 0.6.2

### Patch Changes

- @owf/identity-common@0.6.2

## 0.6.1

### Patch Changes

- Updated dependencies [bf9b7c8]
  - @owf/identity-common@0.6.1

## 0.6.0

### Minor Changes

- 21eeccb: Apply metadata policies as described in Section 6.1 of OpenID Federation 1.0.
  
  - `subset_of`, `superset_of` and `one_of` have no effect when the metadata parameter is absent. Before, `subset_of` and `superset_of` rejected the chain.
  - `superset_of` checks that the metadata parameter contains every operator value. Before, the check was reversed, so `superset_of: ["a"]` rejected `["a", "b"]` and accepted `[]`.
  - `subset_of` may leave an empty array, which stays the value of the metadata parameter, also when `essential` is `true` (Table 1). Before, the parameter was removed, and `essential` rejected an empty array. Merging two `subset_of` without common values results in `[]` instead of a policy error; `one_of` still requires common values.
  - `essential` values are merged with a logical OR. Before, the superior's value was kept, so a subordinate could not make a parameter essential. `MetadataMergeStrategy.SuperiorFollowsIfTrue` is replaced by `LogicalOr`; `subset_of` uses the new `IntersectionMayBeEmpty`.
  - Operators are applied only to entity types the metadata has, and the `metadata` of the superior's subordinate statement only to entity types of the subject's entity configuration (Section 3.1.1). Before, `add`, `default` and `value` and the superior's `metadata` created an entity type the subject does not have.
  - `scope` is processed as a string array and written back as a space-separated string, so `subset_of`, `superset_of`, `add` and `default` work on it. Before, `subset_of` and `superset_of` rejected the chain.
  - `value` may be combined with `add`, `default`, `one_of`, `subset_of` and `superset_of`. The conditions of Section 6.1.3.1 on combinations are checked for each policy and for the merged policy, for example that the values of `add` are a subset of `subset_of`. A `value` of `null` counts as no values. Additional operators that are not understood no longer count as a disallowed combination.
  
  `resolveTrustChains` also checks the claims of each statement against its kind (Section 3.2): entity configurations with `metadata_policy`, `metadata_policy_crit`, `constraints` or `source_endpoint`, or with an empty `authority_hints` array, and subordinate statements with `authority_hints`, `trust_marks`, `trust_mark_issuers` or `trust_mark_owners` are rejected. As no additional policy operators are supported, a subordinate statement with `metadata_policy_crit` is rejected (Section 3.1.3). Before, an operator listed there was ignored unless the same statement used it.
- 21eeccb: Add `@owf/openid-federation`, previously published as `@openid-federation/core` from the `openid-federation-ts` repository. It is versioned together with the other `@owf/*` packages. Compared to `@openid-federation/core` 0.2.1, besides the changes listed separately:
  
  - The schemas are `zod` 4 schemas. Schemas that keep unknown properties use `.loose()`.
  - The package is ESM-only, like the other packages of this repository. Type declarations are exposed through the `types` export condition, and `require('@owf/openid-federation')` loads the ESM build, which needs a Node.js version that supports `require(esm)` (Node.js 20.19 and later, or 22.12 and later).
  - The `buffer` dependency is removed, encoding uses `@owf/identity-common`. The header, payload and signature of a JWT must be base64url encoded, base64 is no longer accepted.
  - Without a `fetchCallback`, `globalThis.fetch` is used, resolved on every request. Before, `global.fetch` was read, which is not defined in browsers.
  - `base64ToBase64URL` and `hasMediaType` are removed. Use `base64url` and `isMediaType` from `@owf/identity-common`.
- 21eeccb: Validate trust chains as described in Section 10 of OpenID Federation 1.0.
  
  `resolveTrustChains` now:
  
  - uses `fetchCallback` for every request, so callers can apply their outbound request policy;
  - rejects an entity configuration whose `sub` is not the requested entity. Before, any URL in `authority_hints` could serve an entity configuration claiming to be a trust anchor, with its own keys and fetch endpoint, and the chain was accepted;
  - checks signatures as Section 10.2 requires: the leaf's entity configuration with a key of the subordinate statement about it, each subordinate statement with a key the next statement lists for its issuer, and the last one with the trust anchor's keys. Before, a subordinate statement was checked with the keys the intermediate published itself. Each subordinate statement must have the requested `iss` and `sub`;
  - checks `iat` and `exp` of every statement, including the leaf and intermediate entity configurations (`currentDate`, `clockSkewSeconds`);
  - rejects statements with `crit` claims that are not in `understoodCriticalClaims`;
  - applies the `max_path_length` and `allowed_entity_types` constraints (entity types are removed before the metadata policies are applied, and a policy can not add them back);
  - compares entity identifiers exactly (Section 16);
  - takes the trust anchors as `trustAnchors`, each with optional pinned `jwks` (out-of-band trust anchor keys); `trustAnchorEntityIds` is removed. Only with `jwks` is the trust anchor's entity configuration checked against keys of the trust anchor as Section 10.2 requires; without them it is trusted on its own signature, as before;
  - bounds the resolution with `maxDepth` (default 8), `maxRequests` (default 64, also the number of entity visits) and `maxAuthorityHints` (default 10, duplicates ignored), so repeated or converging `authority_hints` can not cause exponential work;
  - rejects chains with `naming_constraints`, which are not evaluated yet, and statements whose `iat` or `exp` is not a valid date;
  - returns `jwtChain` (the trust chain as compact JWTs, leaf first) and `expiresAt` (earliest `exp` of the chain) for each chain.
  
  `resolveTrustChainsWithFailures` also returns why each failed path was rejected (openwallet-foundation-labs/openid-federation-ts#12). A leaf whose entity configuration can not be used is now reported as a failure instead of rejecting the promise.
  
  Other fixes:
  
  - `fetchEntityConfiguration` checks that `sub` is the requested entity, `fetchEntityStatement` that `iss` and `sub` are the requested ones.
  - `fetchEntityConfigurationChains` and `fetchEntityStatementChain` are removed: they checked subordinate statements against the keys an intermediate published itself, not as Section 10.2 requires. Use `resolveTrustChains`. `EntityStatementChain` is still exported.
  - Fetch endpoint requests send only `sub` (Section 8.1.1), not `iss`.
  - Requests reject non-2xx responses, compare the content-type without parameters such as `charset` (openwallet-foundation-labs/openid-federation-ts#17), and no longer append an empty `?` to URLs.
  - `OpenIdFederationError` and `PolicyErrorStage` are exported.
- 21eeccb: Read and write entity statements of OpenID Federation 1.0 final only; support for earlier drafts is removed.
  
  - Trust marks use `trust_mark_type` (Sections 3.1.2 and 7.1). The draft `id` is no longer read: a trust mark without `trust_mark_type` is rejected. The `trust_mark_type` of a `trust_marks` entry must be the one of its trust mark JWT.
  - `iat`, `exp` and the other date claims must be NumericDate values (seconds since the epoch, RFC 7519) when statements are parsed and created. ISO strings and `Date` objects are rejected; parsed claims still return `Date` objects (openwallet-foundation-labs/openid-federation-ts#23).
  - Decoded JWTs, such as `trust_marks[].trust_mark`, keep the compact JWT in `jwt`, so a trust mark can be verified.
  - Metadata keeps parameters and entity types the schemas do not define. Before, for example, `token_endpoint` of `oauth_authorization_server` and every unknown entity type were dropped, also from `resolvedLeafMetadata`.
  - `client_registration_types` and `client_registration_types_supported` are optional for all entity types (RECOMMENDED in Sections 5.1.2 and 5.1.3) and accept values other than `automatic` and `explicit`.

### Patch Changes

- 9a3ca9c: Keep the query component of a `federation_fetch_endpoint` (Section 5.1.1 of OpenID Federation 1.0). `sub` is appended with `&`, so a fetch endpoint `https://ta.example.org/fetch?tenant=a` is requested as `https://ta.example.org/fetch?tenant=a&sub=...` instead of `https://ta.example.org/fetch?tenant=a?sub=...`. This applies to `fetchEntityStatement`, `resolveTrustChains` and `resolveTrustChainsWithFailures`.
- @owf/identity-common@0.6.0

## 0.2.1

### Patch Changes

- fab3ff1: fix: Align x5c schema type with RFC 7517 specification

## 0.2.0

### Minor Changes

- 2e2d609: feat: add support for policies

### Patch Changes

- 17ff76b: chore: prepare for release at openwallet foundation
