# @owf/eudi-registration-certificate

## 0.7.0

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
- 21cd668: `verifyRegistrationCertificate` takes `maxStatusListDecompressedBytes`, and `verifyRegistrationCertificateStatus` takes `maxDecompressedBytes`: the size the status list of a registration certificate may inflate to, 16 MiB by default. The response that serves the status list is limited to 16 MiB, or the `statusList` limit of the new `fetchLimits` of the callbacks (see `FetchLimits` of `@owf/identity-common`). A larger response is reported as `status_list_unavailable`, and a larger list as `invalid_status_list`. The `fetch` callback gets `{ type: 'statusList' }` as its third argument.
- f6d2c57: Add CWT registration certificates (`signRegistrationCertificateCwt`, `decodeRegistrationCertificateCwt`), helpers to attach and decode them in mdoc and OpenID4VP requests, and `verifyRegistrationCertificate`, which checks the signature, `iat`/`exp` and the status list.
  
  **Breaking:** `signRegistrationCertificate`, `decodeRegistrationCertificate` and `parseRegistrationCertificate` end in `Jwt`, and the signer takes a `signJwsCallback` of `@owf/jose`. All errors are a `RegistrationCertificateValidationError` with coded `issues`. `RegistrationCertificateError` is removed.
- b42732a: The exports are named `RegistrationCertificate` instead of `WRPRC`.
  
  **Breaking:** replace `WRPRC` with `RegistrationCertificate` in the names of the exports, e.g. `validateWRPRC` to `validateRegistrationCertificate`, `signWRPRC` to `signRegistrationCertificate`, `WRPRCError` to `RegistrationCertificateError` and `zWRPRCPayload` to `zRegistrationCertificatePayload`. Constants start with `REGISTRATION_CERTIFICATE_` instead of `WRPRC_`, e.g. `REGISTRATION_CERTIFICATE_VALIDATION_CODES`, and the builder `wrprc()` is now `registrationCertificate()`. The `name` of the errors and the messages change with it.
- cb487f1: Validation issues have typed codes with their context, and a failed validation throws an error with the same `issues`.
  
  - `@owf/identity-common`: issue codes are a closed union, so `issue.code === 'expired'` narrows the context. Schema issues get a code of `SCHEMA_VALIDATION_CODES` (`missing_value`, `invalid_type`, `invalid_value`, `too_small`, …) instead of the zod code. New: `ValidationIssues`, `parseWithSchema`, `addValidationIssue` and `zTyp`. `@owf/identity-common` now depends on zod.
  - Each package throws its own validation error with `issues`: `TrustedListValidationError`, `LoteValidationError`, `RegistrationCertificateValidationError` and `AccessCertificateValidationError`. Each extends the `ValidationError` of `@owf/identity-common`, not the error of its package.
  - `createAccessCertificate` reports all invalid options at once, with a path into the options.
  - `checkOverAsking` parses the DCQL query with the `dcql` library. A query it rejects gets the issues of `dcql`, with their location in the query and a code of `DCQL_VALIDATION_CODES` or a schema code. A credential query needs an `id`, and the `namespace`/`claim_name` form of earlier drafts gives an `invalid_query` issue (OpenID4VP 1.0 section 6).
  
  **Breaking:** `*Exception` is renamed to `*Error` in these packages, e.g. `WRPRCException` to `WRPRCError`. Zod schemas are named `zFoo` instead of `FooSchema`, e.g. `zTrustedList`. `@owf/identity-common` no longer exports `ValidationIssueParams` and `SchemaIssue`: add an issue with a code in a zod refinement with `addValidationIssue`. `schemaIssueToValidationIssue` takes a zod issue.

### Patch Changes

- 5fff735: Media types are compared with `isMediaType` and JOSE `typ` values with `isJwtTyp`, both from `@owf/identity-common`. New: `CommonMediaTypes` of `@owf/identity-common`, the media types that are not specific to one specification, and `Oauth2MediaTypes` of `@openid4vc/oauth2`, with the JAR request object media type. JARM accepts its `Content-Type` in any casing. A Key Binding JWT and a registration certificate accept their `typ` in any casing and with the `application/` prefix (RFC 7515 Section 4.1.9).
  
  **Breaking:** `isContentType` and `isResponseContentType` are removed from `@openid4vc/utils`. Replace `isContentType(contentType, value)` with `isMediaType(value, contentType)` and `isResponseContentType(contentType, response)` with `isMediaType(response.headers.get('Content-Type'), contentType)`. `MediaTypes` is renamed to `StatusListMediaTypes` in `@owf/token-status-list` and to `MdocMediaTypes` in `@owf/mdoc`. `ContentType` is removed from `@openid4vc/utils`: use `CommonMediaTypes`, and `Oauth2MediaTypes.AuthorizationRequestJwt` for `ContentType.OauthAuthorizationRequestJwt`. The `expectedContentType` of a `ZodFetcher` is a `string`.
- Updated dependencies [90614a9]
- Updated dependencies [f6d2c57]
- Updated dependencies [4e50fca]
- Updated dependencies [ec2ed51]
- Updated dependencies [ec2ed51]
- Updated dependencies [90614a9]
- Updated dependencies [8db5da6]
- Updated dependencies [cb487f1]
- Updated dependencies [163e447]
- Updated dependencies [f6d2c57]
- Updated dependencies [0f663bf]
- Updated dependencies [ebd0b4b]
- Updated dependencies [21cd668]
- Updated dependencies [ec2ed51]
- Updated dependencies [f6d2c57]
- Updated dependencies [5d665bb]
- Updated dependencies [946d9af]
- Updated dependencies [3127af9]
- Updated dependencies [ec2ed51]
- Updated dependencies [946d9af]
- Updated dependencies [21cd668]
- Updated dependencies [21cd668]
- Updated dependencies [5441d63]
- Updated dependencies [21cd668]
- Updated dependencies [cb487f1]
- Updated dependencies [5fff735]
- Updated dependencies [04cfd04]
  - @owf/token-status-list@0.8.0
  - @owf/eudi-jades@0.7.0
  - @owf/cose@0.8.0
  - @owf/crypto@0.8.0
  - dcql@5.0.0
  - @owf/identity-common@0.8.0
  - @owf/jose@0.8.0

## 0.6.0

### Minor Changes

- 23f227b: Add `checkOverAsking(dcqlQuery, credentials)`, which compares the DCQL query of an OpenID4VP request with the `credentials` of a WRPRC and reports every credential and claim the request asks for beyond the registration. It returns `{ valid, issues }` like the validators, with codes from `OVER_ASKING_CODES` and paths into the query. A requested credential needs a registered one of the same format whose `meta` it stays within, and a requested claim a registered claim with the same or a parent path, and with only registered `values` when the registered claim lists them. A credential query without claims only has its credential checked, and a registered credential without claims gives a warning.
- 23f227b: Validators return one list of issues of one shape, so the validators of trusted lists, LoTEs, registration certificates and access certificates can be consumed the same way, for example to show which element of a parsed document conforms and which does not.
  
  **Breaking:** `validateTrustedList`, `validateTrustedListProfile`, `validateLoTE`, `validateLoTEProfile`, `validateWRPRC`, `validateWRPRCPayload`, `validateWRPRCJWTHeader`, `validateLegalPersonWRPRC`, `validateNaturalPersonWRPRC` and `validateAccessCertificate` return `{ valid, issues }` instead of `errors` and `warnings`. Use `validationErrors(result)` for the errors only.
  
  - `@owf/identity-common` adds:
    - `ValidationIssue` (`severity`, `code`, `path`, `message`, and an optional `requirement` and `context`) and `ValidationResult`. The severity is `error`, `warning` or `info`, and only errors make a result invalid. The `path` holds property names and array indices as numbers, and is empty for an issue about the value as a whole.
    - `VALIDATION_CODES`, codes for checks that recur across specifications (`invalid_typ`, `expired`, `not_yet_valid`, `expires_before_issued`), each with a typed context in `ValidationIssueContexts`, e.g. `{ expected, actual }` for `invalid_typ`. `ValidationIssueOf<Code>` types the issues of a validator, so checking the code narrows the context.
    - `schemaIssueToValidationIssue` for zod and other schema issues. A custom zod issue whose `params` are `ValidationIssueParams` gets their code, severity, requirement and context.
    - `toValidationResult`, `validationErrors`, `hasValidationErrors` and `prefixIssuePaths`.
  - Schema issues carry the zod issue code. `@owf/eudi-tl` adds `TRUSTED_LIST_VALIDATION_CODES` and `@owf/eudi-lote` adds `LOTE_VALIDATION_CODES`, the codes of their profile checks.
  - `validateLoTEProfile` no longer adds a summary error for the document as a whole. A document whose `LoTEType` matches none of the profiles gets an `unexpected_lote_type` issue for each profile.
  - `@owf/eudi-registration-certificate`: the issues carry the ETSI TS 119 475 requirement where a check has one. A `typ` other than `rc-wrp+jwt` is reported as `invalid_typ`, and `exp` at or before `iat` as `expires_before_issued` (before: `exp_before_iat`, and `WRPRC_VALIDATION_CODES.EXP_BEFORE_IAT` is now `EXPIRES_BEFORE_ISSUED`). `ValidationError` is removed.
  - `@owf/eudi-access-certificate`: the issues carry a `path` into the access certificate, e.g. `['certificate', 'subject', 'organizationIdentifier']`. The values of `ACCESS_CERTIFICATE_VALIDATION_CODES` are now in lower case, such as `missing_policy`, and `expired` and `not_yet_valid` carry the date as context.

### Patch Changes

- Updated dependencies [23f227b]
  - @owf/identity-common@0.7.0
  - @owf/crypto@0.7.0
  - @owf/eudi-jades@0.6.0

## 0.5.4

### Patch Changes

- Updated dependencies [13a53dc]
  - @owf/crypto@0.6.2
  - @owf/identity-common@0.6.2
  - @owf/eudi-jades@0.5.4

## 0.5.3

### Patch Changes

- Updated dependencies [bf9b7c8]
  - @owf/identity-common@0.6.1
  - @owf/crypto@0.6.1
  - @owf/eudi-jades@0.5.3

## 0.5.2

### Patch Changes

- @owf/crypto@0.6.0
  - @owf/identity-common@0.6.0
  - @owf/eudi-jades@0.5.2

## 0.5.1

### Patch Changes

- @owf/eudi-jades@0.5.1

## 0.5.0

### Minor Changes

- b4105be: Drop the CommonJS build from all packages; only ESM is now published. All environments targeted by this library support ESM natively. This removes the dual-package hazard that caused `instanceof` checks to fail in Metro/Hermes and similar single-module-system runtimes.

### Patch Changes

- 8969b41: Rename `@owf/eudi-wrprc` to `@owf/eudi-registration-certificate`. The API is unchanged; replace the package name in your dependencies and imports.
- Updated dependencies [b4105be]
  - @owf/crypto@0.5.0
  - @owf/eudi-jades@0.5.0
  - @owf/identity-common@0.5.0

## 0.4.2

### Patch Changes

- e6fdf57: Accept national schemes (two letters and `:`, e.g. `HR:DE-...`) as semantic identifier initial characters in `sub`, as allowed by ETSI EN 319 412-1 LEG-5.1.4-03 (7) and NAT-5.1.3-03 (7). They produce the existing unknown-prefix warning instead of an error.
- @owf/eudi-jades@0.4.2
  - @owf/crypto@0.4.2
  - @owf/identity-common@0.4.2

## 0.4.1

### Patch Changes

- 31693aa: replace provides attatation to use only credential, not a link
- f5d57f4: Require the access-certificate subject in WRPRC validation, signing, parsing, and decoding APIs. Validate it against `intermediary.sub` when present and `sub` otherwise.
- @owf/crypto@0.4.1
  - @owf/eudi-jades@0.4.1
  - @owf/identity-common@0.4.1

## 0.4.0

### Minor Changes

- b7e7f15: Add `dateToSeconds`, `secondsToDate` and `nowInSeconds` to `@owf/identity-common`, and use them in `@owf/eudi-wrprc` in place of inline `* 1000` and `/ 1000` arithmetic.
  
  Type the codes that `validateWRPRCPayload` emits. `WRPRC_VALIDATION_CODES` and the `WRPRCValidationCode` union are exported, so a calling application can branch on a specific failure instead of matching message text. The `code` field stays open to strings because schema issues forward zod's own codes. `ValidationError` and `ValidationResult` are now exported as well.
- 947007b: Add an optional `jti` claim to the WRPRC payload, so a certificate can be referenced by an identifier.
  
  - `WRPRCPayloadSchema` accepts an optional non-empty `jti` (RFC 7519). ETSI TS 119 475 does not define the claim, so it is never generated: a payload built without one carries no identifier, and payloads issued elsewhere without one stay valid.
  - New builder method `certificateId(id)` sets `jti`, for issuers that have their own identifier scheme. Pass `crypto.randomUUID()` for a random one.
- caf884c: Bring the WRPRC implementation in line with the letter of ETSI TS 119 475 v1.2.1, so it interoperates with other SDKs that implement the specification as written.
  
  - Produce and check a real JAdES B-B signature, as GEN-5.2.1-04 requires. `signWRPRC` now builds the token through `@owf/eudi-jades`, so the protected header carries the `iat` claimed signing time of ETSI TS 119 182-1 alongside `typ`, `alg` and `x5c`, and a `signingTime` option pins it. `decodeWRPRC` rejects tokens that fail the B-B profile. Table 5 is a minimum set rather than an exhaustive one, so the header keeps requiring `iat`.
  - Accept the full JAdES B-B algorithm set of ETSI TS 119 182-1 clause 5.1.2 (`PS256`/`PS384`/`PS512` and `EdDSA` in addition to `ES*` and `RS*`), exported as `WRPRC_JWS_ALGORITHMS`.
  - Restrict `provides_attestations` to `Credential` objects with `format` and `meta` only, as required by Table 8 and Annex B.2.1, so wallets do not have to resolve external scheme URLs or interpret claim queries to understand the provided attestations.
  - Accept the anticipated `claims` and `intermediary.name` spellings when parsing, normalizing both to the published `claim` and `intermediary.sname`. Writing stays on the published edition unless the new `dialect` option selects `WRPRC_DIALECTS.DRAFT`, which is unstable and not the default. `normalizeWRPRCPayload`, `toWRPRCDialect` and `parseWRPRCPayload` expose the mapping.
  - Allow DCQL claims path pointers to contain integers and `null` in addition to strings, matching the pointer semantics the specification defers to.
  - Correct the identifier type to prefix mapping, which differs between legal persons (Table 2, where the TIN type maps to `VAT`) and natural persons (Table 4). `IDENTIFIER_TYPE_TO_PREFIX` is replaced by `LEGAL_PERSON_IDENTIFIER_PREFIXES` and `NATURAL_PERSON_IDENTIFIER_PREFIXES`, and `getIdentifierPrefix` takes a subject type. `TAX` is no longer accepted as a natural person prefix, and `TIN` no longer as a legal person one.
  - Warn through the new `unknown_identifier_prefix` code when `sub` uses initial characters outside Tables 2 and 4. The prefix lists previously fed an empty `if` block, so they had no effect at all.
  - Fix `WRPRCBuilder.serviceDescription`, which grouped by language. `srv_description` is an array of services each localized into several languages (B.2.1, Annex C), so localizing one service into two languages produced two services instead of one. Consecutive calls now localize the same service, and repeating a language starts the next one.
  - Warn when a Service_Provider WRPRC omits `credentials` or `purpose` (GEN-5.2.4-06) via the new `missing_credentials` and `missing_purpose` validation codes.
  
  The README now documents which editorial defects of the specification the library reproduces on purpose, notably the singular `claim` subfield inside `Credential` and `intermediary.sname` from the normative Table 10 rather than `name` from the informative Annex C example.
  
  Breaking: `addProvidedAttestation` only accepts provided attestation credential objects with `format` and `meta`, and payload parsing rejects scheme URL strings or `claim` / `claims` entries in `provides_attestations`.
- b7e7f15: Align the WRPRC payload with ETSI TS 119 475 v1.2.1.
  
  - Add the Table 10 optional attributes `public_body`, `exp` and `intermediary.sname`, the latter replacing `intermediary.name`. Add the `act` claim required by GEN-5.2.4-09, and `intended_use_id` from Table 9.
  - Add `iat` to `WRPRCPayloadSchema`. Table 7 lists it as a payload field, and the builder set it already, but `build()` parsed it away, so every payload it returned lost its issuance time.
  - Accept entitlements in the Annex A.2 OID form as well as the URI form (GEN-5.2.4-03). Values outside Annex A still raise a warning.
  - Validate that `exp` falls at most 12 months after `iat` (GEN-5.2.4-08), and that `act.sub` matches the intermediary identifier under intermediation (GEN-5.2.4-09).
  
  Breaking: payloads carrying `intermediary.name`, and payloads without `iat`, no longer validate.

### Patch Changes

- Updated dependencies [b7e7f15]
- Updated dependencies [5934a14]
- Updated dependencies [a986752]
- Updated dependencies [c55b5d0]
- Updated dependencies [65a7173]
- Updated dependencies [65a7173]
  - @owf/identity-common@0.4.0
  - @owf/eudi-jades@0.4.0
  - @owf/crypto@0.4.0

## 0.3.2

### Patch Changes

- d0c90bd: add json schema generator
- be9f7cf: Rename content to value field to align with spec
- 06f362e: move iat to header for jwt and cwt
- 9806aba: provides attestation is a list of strings
  - @owf/crypto@0.3.2
  - @owf/identity-common@0.3.2

## 0.3.1

### Patch Changes

- @owf/crypto@0.3.1
- @owf/identity-common@0.3.1

## 0.3.0

### Patch Changes

- Updated dependencies [353df0c]
  - @owf/identity-common@0.3.0
  - @owf/crypto@0.3.0

## 0.2.0

### Patch Changes

- b79d4ba: align package json for export
- 293e5ec: Also include commonjs builds
- 0bc3d9a: fix purpose field from value to content
- Updated dependencies [b79d4ba]
- Updated dependencies [7ef6497]
- Updated dependencies [f50ec6e]
- Updated dependencies [293e5ec]
- Updated dependencies [6bd9c63]
  - @owf/identity-common@0.2.0
  - @owf/crypto@0.2.0
