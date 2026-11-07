# @owf/eudi-lote

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
- 9ab70e1: `validateLoteProfile` in compat mode accepts a Pub-EAA Providers List without `HistoricalInformationPeriod`, as the French EUDI Wallet sandbox publishes it. Strict mode still requires it with value `65535` (TS 119 602 H.1).
  
  On a Pub-EAA Providers List, `validateLoteProfile` looks for the `http://uri.etsi.org/19602/ListOfTrustedEntities/PubEAAProvider/CC` URI in `TEAddress.TEElectronicAddress`, where TS 119 602 H.2 puts it. Compat mode also accepts it in `TEInformationURI`.
  
  **Breaking:** strict mode rejects a Pub-EAA Providers List with the URI only in `TEInformationURI`, such as the EC acceptance list. Validate such a list with `mode: 'compat'`.
- cb487f1: Validation issues have typed codes with their context, and a failed validation throws an error with the same `issues`.
  
  - `@owf/identity-common`: issue codes are a closed union, so `issue.code === 'expired'` narrows the context. Schema issues get a code of `SCHEMA_VALIDATION_CODES` (`missing_value`, `invalid_type`, `invalid_value`, `too_small`, …) instead of the zod code. New: `ValidationIssues`, `parseWithSchema`, `addValidationIssue` and `zTyp`. `@owf/identity-common` now depends on zod.
  - Each package throws its own validation error with `issues`: `TrustedListValidationError`, `LoteValidationError`, `RegistrationCertificateValidationError` and `AccessCertificateValidationError`. Each extends the `ValidationError` of `@owf/identity-common`, not the error of its package.
  - `createAccessCertificate` reports all invalid options at once, with a path into the options.
  - `checkOverAsking` parses the DCQL query with the `dcql` library. A query it rejects gets the issues of `dcql`, with their location in the query and a code of `DCQL_VALIDATION_CODES` or a schema code. A credential query needs an `id`, and the `namespace`/`claim_name` form of earlier drafts gives an `invalid_query` issue (OpenID4VP 1.0 section 6).
  
  **Breaking:** `*Exception` is renamed to `*Error` in these packages, e.g. `WRPRCException` to `WRPRCError`. Zod schemas are named `zFoo` instead of `FooSchema`, e.g. `zTrustedList`. `@owf/identity-common` no longer exports `ValidationIssueParams` and `SchemaIssue`: add an issue with a code in a zod refinement with `addValidationIssue`. `schemaIssueToValidationIssue` takes a zod issue.

### Patch Changes

- Updated dependencies [8db5da6]
- Updated dependencies [ebd0b4b]
- Updated dependencies [ec2ed51]
- Updated dependencies [ec2ed51]
- Updated dependencies [cb487f1]
- Updated dependencies [5fff735]
- Updated dependencies [04cfd04]
  - @owf/crypto@0.8.0
  - @owf/identity-common@0.8.0

## 0.6.0

### Minor Changes

- 5f6197a: Add a `mode` and `allowedTerritories` option to `validateLoTEProfile`, and a `mode` option to `validateLoTE`, to validate lists in use that deviate from ETSI TS 119 602, such as the German EUDI Wallet lists.
  
  - `mode: 'strict'` (default) validates as before. `mode: 'compat'` also accepts a `LoTELegalNotice` that is an array of localized URIs, `PolicyOrLegalNotice` items with both keys, and on a PID Providers List a `ServiceStatus` of `http://uri.etsi.org/19602/PidProvidersList/SvcStatus/notified` with a `StatusStartingTime`.
  - `allowedTerritories` sets the accepted `SchemeTerritory` values in compat mode, `['EU']` by default. Strict mode requires `EU` (TS 119 602 D to I) and throws a `LoTEException` when `allowedTerritories` is passed.
  
  ```ts
  validateLoTEProfile(lote, LoTEProfile.EUPIDProvidersList, { mode: 'compat', allowedTerritories: ['DE'] })
  ```

- 5f6197a: The `EUPubEAAProvidersList` profile rejected every list that follows ETSI TS 119 602 Annex H, as it forbade `ServiceStatus` and `StatusStartingTime`. It now requires a `ServiceStatus` on each service, either `http://uri.etsi.org/19602/PubEAAProvidersList/SvcStatus/notified` or `.../withdrawn`, and accepts a `StatusStartingTime`.
  
  BREAKING: A valid Pub-EAA Providers List can now list withdrawn services. Only trust notified ones: the valid result of `validateLoTEProfile` has the trusted entities with only their notified services as `notifiedTrustedEntities`, and `getNotifiedTrustedEntities(lote)` returns the same.
- df04961: Align `validateLoTE` with the ETSI TS 119 602 v1.1.1 JSON schema. The schema is vendored unchanged with its licence, and a test runs it with ajv over the same documents as `validateLoTE`; the few places where the two still differ are listed in that test with their reason (see below). Rules that only the EU lists impose moved from the base schema to the profiles, so `validateLoTEProfile` still applies them.
  
  Now accepted by `validateLoTE`:
  
  - a list without `TrustedEntitiesList`, as the EC lists publish a list with no entities;
  - `LoTELegalNotice` as a plain string, as in the JSON schema, as well as a localized string;
  - a service supply point without `ServiceType`, and a postal address without `Locality` or `PostalCode`;
  - RFC 3339 date-times with a UTC offset, a lowercase `t` or `z`, or a leap second, not only `Z`;
  - empty strings where the JSON schema allows them: `lang`, `value`, a certificate's `val`, `MimeType`;
  - a `Country` that is not a 2-letter code, and a `ServiceDigitalIdentity` with no identity;
  - any URI as a certificate's `encoding` and any string as its `specRef`, and `oct` as a JWK `kty`.
  
  Now rejected by `validateLoTE`, as the JSON schema does: a `PolicyOrLegalNotice` that is empty, that has an item with neither key, that mixes policies and legal notices, or whose items all carry both `LoTEPolicy` and `LoTELegalNotice` (the schema's `oneOf`: every item has `LoTEPolicy`, or every item has `LoTELegalNotice`, not both). The exported `PkiObjectSchema` also requires its `encoding` to be a URI, as the schema's `pkiOb` does.
  
  Still checked by the EU profiles in `validateLoTEProfile`, on the scheme information, the pointers to other lists, the entities and the service history: non-empty `lang` and `value`, a 2-letter `Country`, at least one digital identity, a non-empty certificate `val`, `encoding` `urn:ietf:params:tls-cert-type:x509` and `specRef` `RFC5280` when present, no `oct` key, a non-empty `MimeType`.
  
  Known differences from the JSON schema, kept on purpose: `validateLoTE` still accepts an empty `TrustedEntitiesList`, an entity without `TEInformationURI`, a localized `LoTELegalNotice`, empty optional arrays, an `OKP` key, a non-integer `HistoricalInformationPeriod`, a `ServiceType` that is not a URI and unknown properties. It rejects a few values the schema's formats let through: a URI that the WHATWG URL parser refuses (a port above 65535, for example), a date-time with a space instead of `T` or an offset without a colon, and integers above 2^53 - 1.
  
  Fixed: the EUEAAProvidersList and EUPubEAAProvidersList profiles rejected every list, because their expected `StatusDeterminationApproach` ended in a stray `"`. The profiles read `ListIssueDateTime` and `NextUpdate` from their RFC 3339 fields for the 6-month rule, so a leap second, which `new Date()` turns into NaN, no longer lets any `NextUpdate` through.
  
  Other changes:
  
  - `createLoTE` leaves `TrustedEntitiesList` out when there are no entities, instead of writing `[]`, which the JSON schema rejects (`minItems: 1`), and writes no key for an optional field left undefined.
  - `removeTrustedEntity` removes the key when the last entity goes. When no entity matches, it returns the list as it was: it no longer adds the key to a list that had none.
  - `ServiceBuilder.addEndpoint(uri)` adds a supply point without `ServiceType`; `addEndpoint(type, uri)` is unchanged.
  - New exports: `PolicyOrLegalNoticeListSchema` and `hasDigitalIdentity`.
  
  Breaking type and behaviour changes:
  
  - `LoTE.TrustedEntitiesList` may be `undefined`: check it before iterating, including on lists made by `createLoTE` without entities.
  - `PolicyOrLegalNotice[].LoTELegalNotice` may be a `string` or a `{ lang, value }` object: reading `.value` alone gets `undefined` on a string.
  - `X509CertificateRef.encoding` and `.specRef` are typed `string`, no longer the literals `urn:ietf:params:tls-cert-type:x509` and `RFC5280`.
  - `JWKPublicKey.kty` adds `oct`.
  - `validateLoTE`, `assertValidLoTE` and the `trustedEntity()` and `service()` builders check the JSON schema rules only. A list or entity that failed them before may now pass with a 3-letter country, an empty name or no service identity: run `validateLoTEProfile` for the EU rules.
  - `validateLoTE` rejects the `PolicyOrLegalNotice` forms listed above, which it used to accept, and `PkiObjectSchema` rejects an `encoding` that is not a URI.
- 5f6197a: `validateLoTE` and `validateLoTEProfile` return the validated document as `lote` when it is valid. `validateLoTE` types it as a `LoTEDocument`, or in compat mode as the new `CompatLoTEDocument`. `validateLoTEProfile` also returns the LoTEType of the matched profile as `loteType`, which narrows `lote` to the new `LoTEProfileDocument` of that profile, with the `LoTEType`, `ServiceTypeIdentifier` and `ServiceStatus` values the profile allows. `LOTE_TYPES` is exported to compare `loteType` with. `assertValidLoTE` takes a `mode` option too.
  
  ```ts
  const result = validateLoTEProfile(lote, [LoTEProfile.EUPIDProvidersList, LoTEProfile.EUPubEAAProvidersList])
  if (result.valid && result.loteType === LOTE_TYPES.EUPubEAAProvidersList) {
    // 'http://uri.etsi.org/19602/PubEAAProvidersList/SvcStatus/notified' | '.../withdrawn'
    result.lote.LoTE.TrustedEntitiesList?.[0]?.TrustedEntityServices[0]?.ServiceInformation.ServiceStatus
  }
  ```
  
  **Breaking:** `ValidationResult` is now a union on `valid`. A value you build yourself needs `lote` when `valid` is `true`. A profile now reports a wrong `LoTEType`, `LoTEVersionIdentifier`, `StatusDeterminationApproach`, `ServiceTypeIdentifier` or `ServiceStatus` before its other rules, which it checks once these pass.
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

## 0.5.4

### Patch Changes

- Updated dependencies [13a53dc]
  - @owf/crypto@0.6.2
  - @owf/identity-common@0.6.2

## 0.5.3

### Patch Changes

- Updated dependencies [bf9b7c8]
  - @owf/identity-common@0.6.1
  - @owf/crypto@0.6.1

## 0.5.2

### Patch Changes

- @owf/crypto@0.6.0
  - @owf/identity-common@0.6.0

## 0.5.1

No changes in this release.

## 0.5.0

### Minor Changes

- b4105be: Drop the CommonJS build from all packages; only ESM is now published. All environments targeted by this library support ESM natively. This removes the dual-package hazard that caused `instanceof` checks to fail in Metro/Hermes and similar single-module-system runtimes.

### Patch Changes

- Updated dependencies [b4105be]
  - @owf/crypto@0.5.0
  - @owf/identity-common@0.5.0

## 0.4.2

### Patch Changes

- @owf/crypto@0.4.2
  - @owf/identity-common@0.4.2

## 0.4.1

### Patch Changes

- @owf/crypto@0.4.1
  - @owf/identity-common@0.4.1

## 0.4.0

### Patch Changes

- Updated dependencies [b7e7f15]
- Updated dependencies [5934a14]
- Updated dependencies [65a7173]
- Updated dependencies [65a7173]
  - @owf/identity-common@0.4.0
  - @owf/crypto@0.4.0

## 0.3.2

### Patch Changes

- d87e13b: Simplifies the errors returned by `validateLoTEProfile` by pre-matching the given LoTE to the corresponding profiles' type identifiers:

  - When no type matches, the error clearly states that the LoTE Type doesn't match any of the given profiles.
  - When one type matches, but fails along the verification, only the errors of this profile are returned for clarity.
  - @owf/crypto@0.3.2
  - @owf/identity-common@0.3.2

## 0.3.1

### Patch Changes

- 541992b: Improve the error detail with profile information when validating a LoTE against a union of profiles.
  - @owf/crypto@0.3.1
  - @owf/identity-common@0.3.1

## 0.3.0

### Patch Changes

- Updated dependencies [353df0c]
  - @owf/identity-common@0.3.0
  - @owf/crypto@0.3.0

## 0.2.0

### Patch Changes

- ce47b64: Allow custom nextUpdate and listIssueDateTime in updateLoTEVersion
- b79d4ba: align package json for export
- f50ec6e: add lote package

  add package-specific exception classes (`CryptoException`, `LoTEException`, `IdentityCommonException`) extending a shared `IdentityException` base class in `@owf/identity-common`, replacing plain `Error` throws across all packages. Refactor `SLException` to also extend `IdentityException`.

- 293e5ec: Also include commonjs builds
- 1b68a03: Add support for validating a LoTE document against known LoTE profiles.
- 7021991: Correctly match distribution points and uri values are URIs.
- 9489bed: Export LoTE profile types and functions.
- Updated dependencies [b79d4ba]
- Updated dependencies [7ef6497]
- Updated dependencies [f50ec6e]
- Updated dependencies [293e5ec]
- Updated dependencies [6bd9c63]
  - @owf/identity-common@0.2.0
  - @owf/crypto@0.2.0

## 0.1.0

### Patch Changes

- f50ec6e: add lote package

  add package-specific exception classes (`CryptoException`, `LoTEException`, `IdentityCommonException`) extending a shared `IdentityException` base class in `@owf/identity-common`, replacing plain `Error` throws across all packages. Refactor `SLException` to also extend `IdentityException`.

- Updated dependencies [7ef6497]
- Updated dependencies [f50ec6e]
  - @owf/identity-common@0.1.0
  - @owf/crypto@0.1.0
