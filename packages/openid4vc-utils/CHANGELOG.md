# @openid4vc/utils

## 0.10.0

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
- 0060df2: **Breaking:** `Oauth2Error`, `Openid4vciError` and `Openid4vcBaseError` extend `IdentityError` of `@owf/identity-common`. Their `name` is their class name. `Oauth2Error` and `Openid4vciError` no longer append the message of their `cause`.
- 0060df2: Schema issues have the codes of `@owf/identity-common`, such as `missing_value` or `invalid_format`, instead of `invalid_value`.
  
  **Breaking:** values the specifications don't allow to be empty are rejected when empty, e.g. `client_id`, `nonce`, `c_nonce`, `pre-authorized_code`, `vct`, `access_token` and `jti`. `dpop_signing_alg_values_supported` rejects `none` (RFC 9449 Section 4.2).
- 0f663bf: Every request reads its response within the new `fetchLimits` of `CallbackContext` (see `FetchLimits` of `@owf/identity-common`), 10 MiB per response by default. Before, a response of any size was read, also to put its body in an `InvalidFetchResponseError`. The `fetch` callback gets what is requested as its third argument, an `Openid4vcFetchType` such as `{ type: 'accessTokenRequest' }`, `{ type: 'credentialRequest' }` or `{ type: 'jwks' }`, so it can apply its own policy per type. The functions that take a `fetch` option, such as `resolveCredentialOffer`, `requestNonce`, `fetchClientMetadata` and `fetchJarRequestObject`, take `fetchLimits` next to it, and `resourceRequest` takes the `type` of what it requests.
  
  **Breaking:** `createFetcher(callbacks, type)` and `createZodFetcher(callbacks, type)` of `@openid4vc/utils` take the `fetch` and `fetchLimits` of the callbacks and the type of the request, instead of a `fetch`, and the fetch they return takes a `string` URL. `fetchWellKnownMetadata` of `@openid4vc/oauth2` requires the `type` option, `'authorizationServerMetadata'` or `'credentialIssuerMetadata'`. `Fetch` is the `FetchCallback` of `@owf/identity-common`, which the global `fetch` still satisfies. A successful response of an unexpected content type throws the `IdentityCommonError` of `@owf/identity-common` instead of an `InvalidFetchResponseError`.
- 0060df2: **Breaking:** `@openid4vc/utils` drops its copies of the `@owf/identity-common` helpers, `ValidationError`, `zNumericDate` and its `buffer` dependency:
  
  | Removed from `@openid4vc/utils` | Use from `@owf/identity-common` |
  | --- | --- |
  | `decodeUtf8String`, `encodeToUtf8String` | `stringToBytes`, `bytesToString` |
  | `encodeToBase64Url`, `encodeToBase64` | `base64url.encode`, `base64.encode` |
  | `decodeBase64` | `base64.decode` or `base64url.decode` |
  | `dateToSeconds` | `dateToSeconds` |
  | `OrPromise`, `isJwtTyp`, `zTyp`, `parseWithErrorHandling`, `BaseSchema`, `ValidationError`, `zNumericDate` | the same names |
  
  **Breaking:** the `@openid4vc` packages throw the `ValidationError` of `@owf/identity-common`, with `issues` instead of `zodError`. `formatZodError` is removed. The `result` of a `ZodFetcher` and the `*Result` fields of the `@openid4vc/openid4vci` responses are a `SchemaParseResult` with `issues`.
  
  The packages no longer call `z.config` on import.
- 5fff735: Media types are compared with `isMediaType` and JOSE `typ` values with `isJwtTyp`, both from `@owf/identity-common`. New: `CommonMediaTypes` of `@owf/identity-common`, the media types that are not specific to one specification, and `Oauth2MediaTypes` of `@openid4vc/oauth2`, with the JAR request object media type. JARM accepts its `Content-Type` in any casing. A Key Binding JWT and a registration certificate accept their `typ` in any casing and with the `application/` prefix (RFC 7515 Section 4.1.9).
  
  **Breaking:** `isContentType` and `isResponseContentType` are removed from `@openid4vc/utils`. Replace `isContentType(contentType, value)` with `isMediaType(value, contentType)` and `isResponseContentType(contentType, response)` with `isMediaType(response.headers.get('Content-Type'), contentType)`. `MediaTypes` is renamed to `StatusListMediaTypes` in `@owf/token-status-list` and to `MdocMediaTypes` in `@owf/mdoc`. `ContentType` is removed from `@openid4vc/utils`: use `CommonMediaTypes`, and `Oauth2MediaTypes.AuthorizationRequestJwt` for `ContentType.OauthAuthorizationRequestJwt`. The `expectedContentType` of a `ZodFetcher` is a `string`.

### Patch Changes

- 755e2eb: `InvalidFetchResponseError` no longer puts the response body into its message, and `createZodFetcher` throws it without quoting the body when a response is not valid JSON. The fetched URL can be chosen by whoever sent a request, such as a `credential_offer_uri`, and the message could return the first 1000 characters of an internal endpoint's response to them. The body stays available as `textResponse`.
  
  `resolveCredentialOffer` only fetches a `credential_offer_uri` that is an https URL (OpenID4VCI 1.0 Section 4.1). `resolveOpenid4vpAuthorizationRequest` fetches the `client_metadata_uri` with `callbacks.fetch` instead of the global `fetch`, so a wallet that restricts the URLs it requests also restricts this one, and `zClientMetadata` only accepts an https `jwks_uri`. `zDataUrl` only accepts a string that starts with `data:`, so `logo_uri` and the display images of credential issuer metadata no longer accept, for example, an http URL with `data:` in its query.
- Updated dependencies [0f663bf]
- Updated dependencies [ebd0b4b]
- Updated dependencies [21cd668]
- Updated dependencies [ec2ed51]
- Updated dependencies [ec2ed51]
- Updated dependencies [cb487f1]
- Updated dependencies [5fff735]
- Updated dependencies [04cfd04]
  - @owf/identity-common@0.8.0

## 0.9.2

### Patch Changes

- Updated dependencies [23f227b]
  - @owf/identity-common@0.7.0

## 0.9.1

### Patch Changes

- @owf/identity-common@0.6.2

## 0.9.0

### Patch Changes

- bf9b7c8: Add `createAcceptHeader`, which asks for media types in order of preference with decreasing `q` values, never below 0.1, and drops duplicates. `createZodFetcher` now uses it, so `@openid4vc/utils` depends on `@owf/identity-common`.
- 34bd5c9: Requests made with `createZodFetcher` now send the expected content types as the `Accept` header, unless the request already sets one. The first content type is preferred, and later ones get decreasing `q` values. Before, the expected content types were only checked against the response `Content-Type`.
- Updated dependencies [bf9b7c8]
  - @owf/identity-common@0.6.1

## 0.8.2

No changes in this release.

## 0.8.1

### Patch Changes

- 4ae057c: Accept the JWT `typ` header in its full media type form (`application/openid4vci-proof+jwt`) and in any casing, as RFC 7515 Section 4.1.9 requires. This applies to client attestations, client attestation PoPs, JAR request objects, access tokens, credential request proofs, key attestations and signed credential issuer metadata. Created JWTs still use the short lowercase form. `@openid4vc/utils` adds `isJwtTyp(value, typ)` for the check, and `zTyp(typ)`, a schema that uses it. It keeps `typ` as sent, so the `typ` of the parsed header types is now `string`.

## 0.8.0

### Patch Changes

- 03a2040: Security fix: `encodeWwwAuthenticateHeader`, and so `Oauth2ResourceUnauthorizedError.toHeaderValue()`, always returns a valid header value. Control and non-ASCII characters are replaced with a space and an `error_description` longer than 500 characters is truncated, so a value taken from the request can no longer inject a header or make setting the header throw.
  
  `parseWwwAuthenticateHeader`, and so `Oauth2ResourceUnauthorizedError.fromHeaderValue()`, unescapes every escaped character in a quoted string (`\\` becomes `\`), not only an escaped quote.

## 0.7.0

### Patch Changes

- 1beaa04: Normalize the `htu` claim of a DPoP proof the same way as the request URL before comparing them, so query and fragment are ignored (RFC 9449 §4.3) and an uppercase host or explicit default port no longer cause a mismatch (RFC 3986 §6.2.2, §6.2.3). `zHttpsUrl` now accepts the URL scheme case-insensitively (RFC 3986 §3.1).
- 5d2179b: Accept data urls of the form "data:image/svg+xml;...". Previously usage of data urls with media type svg+xml would lead to errors when validating metadata.

## 0.6.0

### Patch Changes

- 18f267c: Omit absent `error`, `error_description` and `scope` parameters from the `WWW-Authenticate` header produced by `Oauth2ResourceUnauthorizedError.toHeaderValue()`. Previously they were emitted as bare parameter names (e.g. `Bearer error, error_description, scope`), which is not a valid challenge per RFC 9110 §11.6.1. `encodeWwwAuthenticateHeader` now skips payload entries with an `undefined` value, while `null` values are still encoded as bare parameter names.

## 0.5.6

### Patch Changes

- edfc2b5: Move the `@openid4vc/*` packages from the `oid4vc-ts` repository into `identity-common-ts`. The `@openid4vc/*` packages keep being versioned together, separately from the other packages in this repository.
  
  The packages stay ESM-only. Type declarations are now exposed through the `types` export condition, and `main` points to the ESM build. `require('@openid4vc/oauth2')` loads the ESM build, which needs a Node.js version that supports `require(esm)` (Node.js 20.19 and later, or 22.12 and later).
  
  The builds no longer include copies of code from other `@openid4vc/*` packages. `@openid4vc/oauth2` bundled its own copy of `ValidationError`, so `instanceof ValidationError` checks against the class exported by `@openid4vc/utils` failed for some errors thrown by `@openid4vc/oauth2`. `@openid4vc/openid4vci` and `@openid4vc/openid4vp` bundled copies of `zOauth2ErrorResponse` and `addSecondsToDate`. `@openid4vc/oauth2` now exports the `VerifyClientAttestationOptions` type.

## 0.5.5

## 0.5.4

## 0.5.3

## 0.5.2

## 0.5.1

## 0.5.0

### Minor Changes

- fa29ab6: chore: drop node 18 support. Lowest supported Node.JS version is now 20.19 +

### Patch Changes

- fa29ab6: feat: add support for Node 26

## 0.4.5

### Patch Changes

- 9c0ac58: fix: allow non-integer (decimal) numbers for JWT claims (iat/nbf/exp)

## 0.4.4

### Patch Changes

- 3f3cfe7: chore: better zod errors with more detail of nested errors

## 0.4.3

## 0.4.2

### Patch Changes

- 05af867: fix: add fallback handling when fetch request fails for metadata requests which have multiple URLs to be tried. It's impossible to e.g. detect a CORS exception,
  so instead we try the other URLs in case of a fetch error, and only throw the error if all requests failed.

  This is supported for both fetching credential issuer metadata and authorization server metadata.

## 0.4.1

## 0.4.0

### Minor Changes

- dfa7819: Remove support for the CommonJS/CJS syntax. Since React Native bundles your code, the update to ESM should not cause issues. In addition all latest minor releases of Node 20+ support requiring ESM modules. This means that even if you project is still a CommonJS project, it can now depend on ESM modules. For this reason oid4vc-ts is now fully an ESM module.

## 0.3.0

### Minor Changes

- 70b9740: Add support for OpenID4VCI draft 15. It also includes improved support for client (wallet) attestations, and better support for server side verification.

  Due to the changes between Draft 14 and Draft 15 and it's up to the caller of this library to handle the difference between the versions. Draft 11 is still supported based on Draft 14 syntax (and thus will be automatically converted).

- fccae5c: chore: update to zod 4. Although the public API has not changed, it does impact the error messages and some of the error structures
- 70b9740: fix typo in param from authorizationServerMetata to authorizationServerMetadata
- 26451d7: Before this PR, all packages used Valibot for data validation.
  We have now fully transitioned to Zod. This introduces obvious breaking changes for some packages that re-exported Valibot types or schemas for example.

### Patch Changes

- c29dd5a: fix: entry file in package.json for cjs to point to the correct file extension
- 158fa8c: feat: support node 22 and 24
- 3b9b88a: fix: create fetch wrapper that always calls toString on URLSearchParams as React Native does not encode this correctly while Node.JS does

## 0.2.0

## 0.1.4

## 0.1.3

### Patch Changes

- d4b9279: chore: create github release

## 0.1.2

### Patch Changes

- 1de27e5: chore: correct formatting for publishing

## 0.1.1

### Patch Changes

- 6434781: docs: add readme

## 0.1.0

### Minor Changes

- 71326c8: feat: initial release
