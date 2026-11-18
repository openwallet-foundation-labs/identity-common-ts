# @owf/eudi-tl

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
- daf02fd: `verifyTrustedListSignature`, `verifyEuLotlSignature`, `loadTrustedList` and `loadEuLotl` verify the signature of a trusted list with the key of the pinned signer certificate (ETSI TS 119 612 clause 5.7.1). Before, a list signed with any key passed as long as a pinned certificate was in its unsigned `KeyInfo`, so a forged EU List of Trusted Lists made any national list trusted. A list with more than one `ds:Signature` is rejected, and `parseTrustedList` reads the scheme information and the trust service providers only from their place in the list, so providers added to unsigned parts of the document are no longer returned. An empty `trustAnchors` fails closed instead of skipping the pin.
  
  **Breaking:** `loadTrustedList` requires `trustAnchors`, because without them it only checked the integrity of the list. Pass the certificates of the scheme operator, or call `verifyTrustedListSignature` and `parseTrustedList` to check the integrity only.
- cb487f1: Validation issues have typed codes with their context, and a failed validation throws an error with the same `issues`.
  
  - `@owf/identity-common`: issue codes are a closed union, so `issue.code === 'expired'` narrows the context. Schema issues get a code of `SCHEMA_VALIDATION_CODES` (`missing_value`, `invalid_type`, `invalid_value`, `too_small`, …) instead of the zod code. New: `ValidationIssues`, `parseWithSchema`, `addValidationIssue` and `zTyp`. `@owf/identity-common` now depends on zod.
  - Each package throws its own validation error with `issues`: `TrustedListValidationError`, `LoteValidationError`, `RegistrationCertificateValidationError` and `AccessCertificateValidationError`. Each extends the `ValidationError` of `@owf/identity-common`, not the error of its package.
  - `createAccessCertificate` reports all invalid options at once, with a path into the options.
  - `checkOverAsking` parses the DCQL query with the `dcql` library. A query it rejects gets the issues of `dcql`, with their location in the query and a code of `DCQL_VALIDATION_CODES` or a schema code. A credential query needs an `id`, and the `namespace`/`claim_name` form of earlier drafts gives an `invalid_query` issue (OpenID4VP 1.0 section 6).
  
  **Breaking:** `*Exception` is renamed to `*Error` in these packages, e.g. `WRPRCException` to `WRPRCError`. Zod schemas are named `zFoo` instead of `FooSchema`, e.g. `zTrustedList`. `@owf/identity-common` no longer exports `ValidationIssueParams` and `SchemaIssue`: add an issue with a code in a zod refinement with `addValidationIssue`. `schemaIssueToValidationIssue` takes a zod issue.

### Patch Changes

- ec2ed51: `TrustedListError` extends `IdentityError` from `@owf/identity-common` instead of `Error`, so `instanceof IdentityError` catches it too.
- Updated dependencies [0f663bf]
- Updated dependencies [ebd0b4b]
- Updated dependencies [21cd668]
- Updated dependencies [ec2ed51]
- Updated dependencies [ec2ed51]
- Updated dependencies [cb487f1]
- Updated dependencies [5fff735]
- Updated dependencies [04cfd04]
  - @owf/identity-common@0.8.0

## 0.6.0

### Minor Changes

- 23f227b: `parseTrustedList` returns the `SchemeTerritory` of the list as `schemeTerritory`, the country code to pass to `getPointerSigningCertificates` to find the certificates its signer must have.
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

## 0.5.4

### Patch Changes

- @owf/identity-common@0.6.2

## 0.5.3

### Patch Changes

- Updated dependencies [bf9b7c8]
  - @owf/identity-common@0.6.1

## 0.5.2

### Patch Changes

- @owf/identity-common@0.6.0

## 0.5.1

No changes in this release.

## 0.5.0

### Minor Changes

- b4105be: Drop the CommonJS build from all packages; only ESM is now published. All environments targeted by this library support ESM natively. This removes the dual-package hazard that caused `instanceof` checks to fail in Metro/Hermes and similar single-module-system runtimes.

### Patch Changes

- Updated dependencies [b4105be]
  - @owf/identity-common@0.5.0

## 0.4.2

### Patch Changes

- @owf/identity-common@0.4.2

## 0.4.1

### Patch Changes

- @owf/identity-common@0.4.1

## 0.4.0

### Minor Changes

- fb11a48: Expose ASN.1 parse options for the X.509 certificates embedded in a trusted list: `parseTrustedList`, `loadTrustedList` and `loadEuLotl` now accept `certificateParseOptions`, forwarding `asn1js.fromBER` resource limits (`maxDepth`, `maxNodes`, `maxContentLength`) so callers can bound the work done on untrusted input. Certificate parsing moved from `@peculiar/x509` to `@peculiar/asn1-x509`, which needs no global `Reflect` polyfill; the derived `subjectKeyIdentifier` values are unchanged
- 59b304c: New package: parse and verify ETSI TS 119 612 XML Trusted Lists (companion to @owf/eudi-lote for TS 119 602 JSON), exposing normalized trust anchors, caller-supplied profile validation, and XAdES signature verification with pinned scheme operator certificates and a caller-installable crypto engine (`setTrustedListCrypto`)
- 59b304c: Follow the EU trust hierarchy: trusted list pointers now expose the certificates the pointed-to list is signed with (`getPointerSigningCertificates`), and the EU LOTL signing certificates ship as pinned default anchors (`EU_LOTL_SIGNING_CERTIFICATES`, `getEuLotlTrustAnchors`, `verifyEuLotlSignature`, `loadEuLotl`) with provenance and a refresh script

### Patch Changes

- Updated dependencies [b7e7f15]
- Updated dependencies [5934a14]
- Updated dependencies [65a7173]
- Updated dependencies [65a7173]
  - @owf/identity-common@0.4.0
