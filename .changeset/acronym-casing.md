---
'@owf/token-status-list': minor
'@owf/eudi-attestation-schema': minor
'@owf/eudi-jades': minor
'@owf/eudi-lote': minor
'@owf/eudi-registration-certificate': minor
'@owf/eudi-tl': minor
'@sd-jwt/core': minor
'@sd-jwt/sd-jwt-vc': minor
'@owf/openid-federation': minor
'@openid4vc/utils': minor
'@openid4vc/openid4vp': minor
---

Abbreviations and names in exports are written as words, e.g. `SdJwt` instead of `SDJwt` or `SDJWT`, and `Openid` instead of `OpenId`.

**Breaking:** rename the exports as follows. The `name` of the renamed errors changes with them. Property names that the specifications define, such as `schemaURIs`, `LoTEType` and `X509SKIs`, don't change.

- `@sd-jwt/core`: `SDJwt` to `SdJwt`, `SDJwtInstance` to `SdJwtInstance`, `SDJWTError` to `SdJwtError`, `SDJWTConfig` to `SdJwtConfig`, `SDJWTCompact` to `SdJwtCompact`, `KBJwt` to `KbJwt`, `KBOptions` to `KbOptions`, `FlattenJSON` to `FlattenJson`, `GeneralJSON` to `GeneralJson`, `DecodedSDJwt` to `DecodedSdJwt` and `getSDAlgAndPayload` to `getSdAlgAndPayload`. The types `kbHeader` and `kbPayload` are now `KbJwtHeader` and `KbJwtPayload`. The methods `toFlattenJSON`, `toGeneralJSON`, `SDJwt.decodeSDJwt`, `SDJwt.encodeSDJwt`, `KBJwt.verifyKB`, `KBJwt.fromKBEncode` and `Jwt.decodeJWT` are now `toFlattenJson`, `toGeneralJson`, `SdJwt.decodeSdJwt`, `SdJwt.encodeSdJwt`, `KbJwt.verifyKb`, `KbJwt.fromKbEncode` and `Jwt.decodeJwt`.
- `@sd-jwt/sd-jwt-vc`: `SDJwtVcInstance` to `SdJwtVcInstance`, `SDJWTVCConfig` to `SdJwtVcConfig`, `SDJWTVCStatusReference` to `SdJwtVcStatusReference` and `VCTFetcher` to `VctFetcher`.
- `@owf/token-status-list`: `getListFromStatusListJWT` to `getListFromStatusListJwt`, `getStatusListFromJWT` to `getStatusListFromJwt`, `JWTClaimNames` to `JwtClaimNames`, `StatusListJWTPayload` to `StatusListJwtPayload`, `StatusListJWTHeaderParameters` to `StatusListJwtHeaderParameters` and `JWTwithStatusListPayload` to `JwtWithStatusListPayload`.
- `@owf/eudi-lote`: `LoTE` to `Lote` in all exports, e.g. `validateLoTE` to `validateLote`, `createLoTE` to `createLote`, `LoTEError` to `LoteError` and `zLoTEDocument` to `zLoteDocument`. Also `JWKPublicKey` to `JwkPublicKey`, `LocalizedURI` to `LocalizedUri`, the builder method `addX509SKI` to `addX509Ski` and the profile option `requireNoPointersToOtherLoTE` to `requireNoPointersToOtherLote`. The list types are written the same way in the `LoteProfile` members and values, the `LOTE_TYPES` keys and the profile schemas, e.g. `LoteProfile.EUPIDProvidersList` to `LoteProfile.EuPidProvidersList`, `zEUPubEAAProvidersList` to `zEuPubEaaProvidersList` and `zMDLProvidersList` to `zMdlProvidersList`. The LoTEType URIs don't change.
- `@owf/eudi-jades`: `JAdESError` to `JadesError`, `JAdESProfile` to `JadesProfile`, `CommitmentOIDs` to `CommitmentOids`, `zOId` to `zOid`, `CompactJWS`, `FlattenedJWS` and `GeneralJWS` (and their `z` schemas) to `CompactJws`, `FlattenedJws` and `GeneralJws`, and the method `toFlattenedJSON` to `toFlattenedJson`.
- `@owf/eudi-attestation-schema`: `SchemaURI` to `SchemaUri`, `SchemaURIMeta` to `SchemaUriMeta`, `SchemaURIBuilder` to `SchemaUriBuilder`, `schemaURI()` to `schemaUri()`, `zSchemaURI` to `zSchemaUri`, `AttestationLoS` to `AttestationLos`, `AttestationLoSValues` to `AttestationLosValues` and the builder method `addSchemaURI` to `addSchemaUri`.
- `@owf/eudi-registration-certificate`: `isPSPSubEntitlement` to `isPspSubEntitlement`, `validateRegistrationCertificateJWTHeader` to `validateRegistrationCertificateJwtHeader`, and `JWT` and `CWT` to `Jwt` and `Cwt` in the header and payload types and schemas, e.g. `zRegistrationCertificateJWTHeader` to `zRegistrationCertificateJwtHeader`.
- `@owf/eudi-tl`: `TSLType` to `TslType`.
- `@openid4vc/utils`: `OpenId4VcBaseError` to `Openid4vcBaseError`.
- `@openid4vc/openid4vp`: `parseOpenid4VpAuthorizationResponsePayload` to `parseOpenid4vpAuthorizationResponsePayload`, `ValidateOpenid4VpAuthorizationResponseResult` (and its `Dcql` and `Pex` variants) to `ValidateOpenid4vpAuthorizationResponseResult`, and the methods `Openid4vpVerifier.createOpenId4vpAuthorizationRequest` and `Openid4vpClient.resolveOpenId4vpAuthorizationRequest` to `createOpenid4vpAuthorizationRequest` and `resolveOpenid4vpAuthorizationRequest`.
- `@owf/openid-federation`: `OpenId` to `Openid` in all exports, e.g. `OpenIdFederationError` to `OpenidFederationError`, `OpenIdProviderMetadata` to `OpenidProviderMetadata` and `openIdProviderEntityMetadata` to `openidProviderEntityMetadata`.
