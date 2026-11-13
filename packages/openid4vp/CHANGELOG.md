# @openid4vc/openid4vp

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
- 0060df2: Every JWT verification takes `now` and `allowedSkewInSeconds` (30 seconds by default), and `Oauth2ResourceServer`, `Openid4vciIssuer`, `Openid4vciClient`, `Openid4vpClient` and `Openid4vpVerifier` take a default `allowedSkewInSeconds`. Key attestations and JAR request objects are verified at the `now` passed in.
  
  DPoP proofs: `maxProofAgeSeconds` allows the skew, an `iat` in the future is always rejected, `assertJtiUniqueness` runs after the signature check, and the `JoseValidationError` of a failed claim is the `cause` of the error response.
  
  A `JoseInvalidArgumentError`, e.g. for a negative skew, is thrown as is instead of as an error response. An expired OpenID4VP request object gives `invalid_request_object`.
  
  A `typ` is accepted in any casing and with the `application/` prefix (RFC 7515 Section 4.1.9). Compare it with `isJwtTyp` of `@owf/identity-common`.
- 0060df2: Schema issues have the codes of `@owf/identity-common`, such as `missing_value` or `invalid_format`, instead of `invalid_value`.
  
  **Breaking:** values the specifications don't allow to be empty are rejected when empty, e.g. `client_id`, `nonce`, `c_nonce`, `pre-authorized_code`, `vct`, `access_token` and `jti`. `dpop_signing_alg_values_supported` rejects `none` (RFC 9449 Section 4.2).
- 0f663bf: Every request reads its response within the new `fetchLimits` of `CallbackContext` (see `FetchLimits` of `@owf/identity-common`), 10 MiB per response by default. Before, a response of any size was read, also to put its body in an `InvalidFetchResponseError`. The `fetch` callback gets what is requested as its third argument, an `Openid4vcFetchType` such as `{ type: 'accessTokenRequest' }`, `{ type: 'credentialRequest' }` or `{ type: 'jwks' }`, so it can apply its own policy per type. The functions that take a `fetch` option, such as `resolveCredentialOffer`, `requestNonce`, `fetchClientMetadata` and `fetchJarRequestObject`, take `fetchLimits` next to it, and `resourceRequest` takes the `type` of what it requests.
  
  **Breaking:** `createFetcher(callbacks, type)` and `createZodFetcher(callbacks, type)` of `@openid4vc/utils` take the `fetch` and `fetchLimits` of the callbacks and the type of the request, instead of a `fetch`, and the fetch they return takes a `string` URL. `fetchWellKnownMetadata` of `@openid4vc/oauth2` requires the `type` option, `'authorizationServerMetadata'` or `'credentialIssuerMetadata'`. `Fetch` is the `FetchCallback` of `@owf/identity-common`, which the global `fetch` still satisfies. A successful response of an unexpected content type throws the `IdentityCommonError` of `@owf/identity-common` instead of an `InvalidFetchResponseError`.
- 0060df2: **Breaking:** JWT handling is built on `@owf/jose`. `@openid4vc/oauth2` no longer exports its JWK, JWA, JWS and JWT helpers:
  
  | Removed from `@openid4vc/oauth2` | Import from `@owf/jose` |
  | --- | --- |
  | `decodeJwt`, `decodeJwtHeader`, `verifyJwt`, `DecodeJwtOptions`, `DecodeJwtResult`, `Jwk`, `JwkSet`, `zJwk`, `zJwkSet`, `JwtHeader`, `JwtPayload`, `zJwtHeader`, `zJwtPayload`, `zCompactJwt`, `zCompactJwe`, `JweEncryptor`, `calculateJwkThumbprint`, `CalculateJwkThumbprintOptions` | the same names |
  | `DecodeJwtHeaderResult` | `ReturnType<typeof decodeJwtHeader>` |
  | `jwtHeaderFromJwtSigner` | `jwsHeaderFromSigner` |
  | `jwtSignerFromJwt({ header, payload })` | `jwsSignerFromHeader({ header, issuer: payload.iss })` |
  | `JwtSigner`, `JwtSignerCustom`, `JwtSignerDid`, `JwtSignerJwk`, `JwtSignerWithJwk`, `JwtSignerX5c` | `JwsSigner`, `JwsSignerCustom`, `JwsSignerDid`, `JwsSignerJwk`, `JwsSignerWithJwk`, `JwsSignerX5c` |
  | `zAlgValueNotNone` | `zJwsAlg` |
  | `jwaSignatureAlgorithmToFullySpecifiedCoseAlgorithm`, `fullySpecifiedCoseAlgorithmToJwaSignatureAlgorithm` | `jwaSignatureAlgorithmToCoseAlgorithm`, `coseAlgorithmToJwaSignatureAlgorithm` |
  | `jwaSignatureAlgorithmArrayToFullySpecifiedCoseAlgorithmArray`, `fullySpecifiedCoseAlgorithmArrayToJwaSignatureAlgorithmArray` | `jwaSignatureAlgorithmsToCoseAlgorithms`, `coseAlgorithmsToJwaSignatureAlgorithms` |
  
  **Breaking:** the `CallbackContext` callbacks `signJwt` and `verifyJwt` are replaced by `signJws` and `verifyJws` (`SignJwsCallback`, `VerifyJwsCallback`). They sign or verify the signing input and return the public key they used. `hash` is a `Hasher` of `@owf/identity-common` that gets the algorithm as `'sha-256'`. The `HashAlgorithm` enum and `HashCallback` type are removed.
  
  **Breaking:** `verifyJwt` takes `jwt` (compact or decoded), `verifyJwsCallback` and `skewSeconds`. `checkExpirationTime`, `checkNotBefore` and `checkIssuedAt` replace `skipTimeBasedValidation`.
  
  **Breaking:** JWTs are verified more strictly. The default skew is 30 seconds instead of 0, also for client attestations. A token issued in the future, a token at its `exp`, a missing `aud` when one is expected, `none`, `HS256`/`HS384`/`HS512` and miscased algorithms are rejected. A header must identify its signer in one way only, and a DID in `kid` must be the `iss`. The JWKS no longer falls back to its only key for an unknown `kid`. Parts that are not base64url, private keys in `jwk` or `cnf.jwk`, and a `crit` that is not understood are rejected.
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
- 2cff118: `parseOpenid4vpAuthorizationRequest` now rejects a DC API or IAE request passed as a URI, as these are always passed as a JSON object (OpenID4VP 1.0 Appendix A.3, OpenID4VCI 1.1 Section 6.2.1.1).
  
  `createOpenid4vpAuthorizationRequest` now rejects an unsigned request whose client identifier prefix requires a signed request, as only `pre-registered` and `redirect_uri` can be used unsigned (OpenID4VP 1.0 Section 5.9.3).
  
  **Breaking:** for a DC API or IAE request, the `authorizationRequest` returned by `createOpenid4vpAuthorizationRequest` is now the JSON object to pass to the wallet instead of a URI: the request payload, or `{ client_id, request }` when signed. Its type now includes these objects, so check for a string before treating it as a URL.
  
  **Breaking:** IAE requests must now be signed. `createOpenid4vpAuthorizationRequest` and `resolveOpenid4vpAuthorizationRequest` reject an unsigned request with the `iae_post` or `iae_post.jwt` response mode. Pass `jar` when creating one.
- 0060df2: **Breaking:** a `verifier_attestation` request is verified as OpenID4VP 1.0 Sections 5.9.3 and 12 require. The attestation in the `jwt` header must verify, its `sub` must be the client identifier, the `redirect_uri` must be one of its `redirect_uris` when it has them, and the request object must be signed with its `cnf` key. The `verifyJws` callback decides whether the issuer is trusted. Recognize the attestation with `isJwtTyp(typ, 'verifier-attestation+jwt')`. New: `verifyVerifierAttestation`, and `verifierAttestation` on the verified JAR request.
- c3e5919: `resolveOpenid4vpAuthorizationRequest` and `verifyJarRequest` reject the request object of a `pre-registered` client when it is signed with a `jwk` or `did` signer, and `Openid4vpAuthorizationRequestError` reports a `pre-registered` client as not authenticated (`isClientAuthenticated` is `false`, `client` is `undefined`). The keys and the `response_uri` of a pre-registered client are registered with the wallet (OpenID4VP 1.0 Section 5.9), which the library cannot check: anyone could sign a request for any `client_id` with a key of their own, and the client was reported as authenticated. For the same reason, `fetchCredentialIssuerMetadata` and `Openid4vciClient.resolveIssuerMetadata` reject signed credential issuer metadata that is signed with a `jwk` or `did` signer (OpenID4VCI 1.0 Section 12.2.3).
  
  **Breaking:** sign the request objects of pre-registered clients with a `kid` that `verifyJws` resolves to a registered key, or with `x5c`. Sign credential issuer metadata with a `kid`, `x5c` or a federation `trust_chain`. Check the registration of a pre-registered client yourself before sending it an error response.

### Patch Changes

- 755e2eb: `InvalidFetchResponseError` no longer puts the response body into its message, and `createZodFetcher` throws it without quoting the body when a response is not valid JSON. The fetched URL can be chosen by whoever sent a request, such as a `credential_offer_uri`, and the message could return the first 1000 characters of an internal endpoint's response to them. The body stays available as `textResponse`.
  
  `resolveCredentialOffer` only fetches a `credential_offer_uri` that is an https URL (OpenID4VCI 1.0 Section 4.1). `resolveOpenid4vpAuthorizationRequest` fetches the `client_metadata_uri` with `callbacks.fetch` instead of the global `fetch`, so a wallet that restricts the URLs it requests also restricts this one, and `zClientMetadata` only accepts an https `jwks_uri`. `zDataUrl` only accepts a string that starts with `data:`, so `logo_uri` and the display images of credential issuer metadata no longer accept, for example, an http URL with `data:` in its query.
- 0060df2: `resolveCredentialOffer` keeps the offer, which can carry the pre-authorized code, out of its error messages. Transaction data that is not base64url encoded UTF-8 or does not validate gives `invalid_transaction_data`.
- 0060df2: - Encrypted JAR request objects verify again.
  - `createOpenid4vpAuthorizationRequest` uses `now` for `iat` and `exp`.
  - `jarm.expiresInSeconds` is the lifetime of a signed JARM response, 10 minutes by default, not its `exp`.
  - A response is not encrypted to a `use: 'sig'` key unless its `kid` names it.
  - `verifyJarmAuthorizationResponse` accepts a `jwk` or `x5c` header, whose trust the `verifyJws` callback decides, checks `exp`, `nbf` and `iat`, and keeps the `@owf/jose` error as `cause`.
- 5fff735: Media types are compared with `isMediaType` and JOSE `typ` values with `isJwtTyp`, both from `@owf/identity-common`. New: `CommonMediaTypes` of `@owf/identity-common`, the media types that are not specific to one specification, and `Oauth2MediaTypes` of `@openid4vc/oauth2`, with the JAR request object media type. JARM accepts its `Content-Type` in any casing. A Key Binding JWT and a registration certificate accept their `typ` in any casing and with the `application/` prefix (RFC 7515 Section 4.1.9).
  
  **Breaking:** `isContentType` and `isResponseContentType` are removed from `@openid4vc/utils`. Replace `isContentType(contentType, value)` with `isMediaType(value, contentType)` and `isResponseContentType(contentType, response)` with `isMediaType(response.headers.get('Content-Type'), contentType)`. `MediaTypes` is renamed to `StatusListMediaTypes` in `@owf/token-status-list` and to `MdocMediaTypes` in `@owf/mdoc`. `ContentType` is removed from `@openid4vc/utils`: use `CommonMediaTypes`, and `Oauth2MediaTypes.AuthorizationRequestJwt` for `ContentType.OauthAuthorizationRequestJwt`. The `expectedContentType` of a `ZodFetcher` is a `string`.
- Updated dependencies [90614a9]
- Updated dependencies [c3e5919]
- Updated dependencies [0060df2]
- Updated dependencies [0f663bf]
- Updated dependencies [ebd0b4b]
- Updated dependencies [21cd668]
- Updated dependencies [ec2ed51]
- Updated dependencies [f6d2c57]
- Updated dependencies [5d665bb]
- Updated dependencies [946d9af]
- Updated dependencies [0060df2]
- Updated dependencies [0060df2]
- Updated dependencies [25c7506]
- Updated dependencies [0060df2]
- Updated dependencies [0060df2]
- Updated dependencies [0f663bf]
- Updated dependencies [0060df2]
- Updated dependencies [755e2eb]
- Updated dependencies [0060df2]
- Updated dependencies [ec2ed51]
- Updated dependencies [cb487f1]
- Updated dependencies [5fff735]
- Updated dependencies [04cfd04]
  - @openid4vc/utils@0.10.0
  - @openid4vc/oauth2@0.10.0
  - @owf/identity-common@0.8.0
  - @owf/jose@0.8.0

## 0.9.2

### Patch Changes

- 153b672: The `client_id` of an unsigned DC API request is now ignored, as required by OpenID4VP 1.0 Appendix A.2. Before, a web page could set any `client_id` in an unsigned request, and the wallet used it as the client. `resolveOpenid4vpAuthorizationRequest` and `validateOpenid4vpClientId` now identify the client by the origin, and the resolved `authorizationRequestPayload` no longer contains the `client_id`.
  
  `getOpenid4vpClientId` now rejects a `client_id` with the reserved `origin:` or `web-origin:` prefix.
- 410d45a: `zJarAuthorizationRequest` now requires `request` or `request_uri`. Before, it matched any object. An unsigned request that failed the regular schema was accepted without validation in `resolveOpenid4vpAuthorizationRequest`, `parseOpenid4vpAuthorizationRequest`, `parsePushedAuthorizationRequest` and `parseInteractiveAuthorizationRequest`. For OpenID4VP, this skipped the https check on `response_uri`, so a wallet could send the presentation over plain http.
- fe62e01: Treat the legacy `w3c_dc_api.jwt` response mode as an encrypted response mode, like `dc_api.jwt`. Before, a holder could send an unencrypted response to a verifier that requested `w3c_dc_api.jwt`.
- Updated dependencies [410d45a]
  - @openid4vc/oauth2@0.9.2
  - @openid4vc/utils@0.9.2

## 0.9.1

### Patch Changes

- Updated dependencies [33576aa]
- Updated dependencies [b74d901]
  - @openid4vc/oauth2@0.9.1
  - @openid4vc/utils@0.9.1

## 0.9.0

### Patch Changes

- Updated dependencies [bf9b7c8]
- Updated dependencies [fa1ce42]
- Updated dependencies [34bd5c9]
  - @openid4vc/utils@0.9.0
  - @openid4vc/oauth2@0.9.0

## 0.8.2

### Patch Changes

- 01b6bd6: Wallets can create and submit OpenID4VP Authorization Error Responses (OpenID4VP 1.0 Section 8.5). `createOpenid4vpAuthorizationResponse` and `submitOpenid4vpAuthorizationResponse` accept an error payload such as `{ error: 'access_denied' }`, and an error response can be created without `jarm` options for a JARM response mode, for when the wallet cannot encrypt it (Section 8.3.1).
  
  `resolveOpenid4vpAuthorizationRequest` throws the new `Openid4vpAuthorizationRequestError` when the request is invalid and its payload is known. It extends `Oauth2ServerErrorResponseError` and carries the `authorizationRequestPayload`, so the wallet can send the `errorResponse` to the verifier. `isClientAuthenticated` tells whether the client was authenticated: the JAR is verified and the client identifier is validated. When it is `false`, for example because the request object signature is invalid, the error can still be sent, but a `redirect_uri` returned by the response endpoint should not be opened. Errors before the payload is known, such as a failure to fetch the request object, are thrown as before.
  
  ```ts
  try {
    await resolveOpenid4vpAuthorizationRequest({ authorizationRequestPayload, responseMode, callbacks })
  } catch (error) {
    if (!(error instanceof Openid4vpAuthorizationRequestError)) throw error
  
    const request = error.authorizationRequestPayload
    // IAE requests are answered through the OpenID4VCI Interactive Authorization Endpoint instead
    if (isOpenid4vpAuthorizationRequestIae(request)) throw error
  
    const { authorizationResponsePayload } = await createOpenid4vpAuthorizationResponse({
      authorizationRequestPayload: request,
      authorizationResponsePayload: { error: error.errorResponse.error },
      callbacks,
    })
  
    if (isOpenid4vpAuthorizationRequestDcApi(request)) {
      // Return the authorizationResponsePayload through the Digital Credentials API
    } else {
      const { response } = await submitOpenid4vpAuthorizationResponse({
        authorizationRequestPayload: request,
        authorizationResponsePayload,
        callbacks,
      })
      // Only follow a returned redirect_uri when error.isClientAuthenticated is true
    }
  }
  ```

- @openid4vc/oauth2@0.8.2
  - @openid4vc/utils@0.8.2

## 0.8.1

### Patch Changes

- Updated dependencies [4ae057c]
  - @openid4vc/utils@0.8.1
  - @openid4vc/oauth2@0.8.1

## 0.8.0

### Patch Changes

- Updated dependencies [2538f35]
- Updated dependencies [3b10167]
- Updated dependencies [03a2040]
  - @openid4vc/oauth2@0.8.0
  - @openid4vc/utils@0.8.0

## 0.7.0

### Patch Changes

- Updated dependencies [1beaa04]
- Updated dependencies [5d2179b]
- Updated dependencies [222ed67]
- Updated dependencies [c0107e4]
  - @openid4vc/oauth2@0.7.0
  - @openid4vc/utils@0.7.0

## 0.6.0

### Patch Changes

- Updated dependencies [0d30e2d]
- Updated dependencies [f3efa25]
- Updated dependencies [83123e8]
- Updated dependencies [2a28c82]
- Updated dependencies [83123e8]
- Updated dependencies [18f267c]
- Updated dependencies [019f316]
  - @openid4vc/oauth2@0.6.0
  - @openid4vc/utils@0.6.0

## 0.5.6

### Patch Changes

- edfc2b5: Ignore the pre-draft-27 `authorization_encrypted_response_alg` and `authorization_encrypted_response_enc` client metadata parameters when the verifier also sends the 1.0 `encrypted_response_enc_values_supported`. Previously a verifier sending both generations of the response encryption metadata could fail with `Invalid authorization_encryption_enc`.
- edfc2b5: Move the `@openid4vc/*` packages from the `oid4vc-ts` repository into `identity-common-ts`. The `@openid4vc/*` packages keep being versioned together, separately from the other packages in this repository.
  
  The packages stay ESM-only. Type declarations are now exposed through the `types` export condition, and `main` points to the ESM build. `require('@openid4vc/oauth2')` loads the ESM build, which needs a Node.js version that supports `require(esm)` (Node.js 20.19 and later, or 22.12 and later).
  
  The builds no longer include copies of code from other `@openid4vc/*` packages. `@openid4vc/oauth2` bundled its own copy of `ValidationError`, so `instanceof ValidationError` checks against the class exported by `@openid4vc/utils` failed for some errors thrown by `@openid4vc/oauth2`. `@openid4vc/openid4vci` and `@openid4vc/openid4vp` bundled copies of `zOauth2ErrorResponse` and `addSecondsToDate`. `@openid4vc/oauth2` now exports the `VerifyClientAttestationOptions` type.
- Updated dependencies [410dae1]
- Updated dependencies [edfc2b5]
  - @openid4vc/oauth2@0.5.6
  - @openid4vc/utils@0.5.6

## 0.5.5

### Patch Changes

- 6060c2d: Add `getAuthorizationServerMetadata` and `getJwks` callbacks to the `CallbackContext`, allowing authorization server metadata and JWK Sets to be resolved without performing a request.
  
  This makes it possible to avoid network requests for metadata and keys that the caller already has (for example an authorization server hosted by the same application, which would otherwise result in an HTTP request to itself when verifying an access token it issued), and to serve metadata and keys from a cache.
  
  Both callbacks are optional. If not provided, or if they return `undefined`, the metadata and JWK Sets are fetched over HTTP as before. `getAuthorizationServerMetadata` can additionally return `null` to indicate the metadata definitively does not exist, so it is not requested again.
  
  Values returned by the callbacks are validated exactly like fetched values: a JWK Set is parsed with the JWK Set schema, and authorization server metadata is parsed with the authorization server metadata schema and must have an `issuer` matching the requested issuer.
  
  The second parameter of the exported `fetchJwks` and `fetchAuthorizationServerMetadata` functions now also accepts an object with `fetch` and the matching resolve callback, in addition to the `Fetch` implementation it accepted before.
- d9524be: Support parsing OpenID4VP Authorization Error Responses. When the wallet returns an authorization error response (e.g. it detected an error with the request, or is unavailable) instead of a successful response containing a `vp_token`, `parseOpenid4VpAuthorizationResponsePayload` (and `parseOpenid4vpAuthorizationResponse`) now throws an `Openid4vpAuthorizationResponseError` with the parsed `errorResponse`, instead of a confusing zod error about the missing `vp_token`.
- Updated dependencies [6060c2d]
  - @openid4vc/oauth2@0.5.5
  - @openid4vc/utils@0.5.5

## 0.5.4

### Patch Changes

- Updated dependencies [63aeaa9]
  - @openid4vc/oauth2@0.5.4
  - @openid4vc/utils@0.5.4

## 0.5.3

### Patch Changes

- Updated dependencies [9c4c66c]
- Updated dependencies [6886ca5]
  - @openid4vc/oauth2@0.5.3
  - @openid4vc/utils@0.5.3

## 0.5.2

### Patch Changes

- Updated dependencies [33adaf0]
  - @openid4vc/oauth2@0.5.2
  - @openid4vc/utils@0.5.2

## 0.5.1

### Patch Changes

- @openid4vc/oauth2@0.5.1
- @openid4vc/utils@0.5.1

## 0.5.0

### Minor Changes

- 675b5b2: Pass allowedSkewInSeconds to verifyClientAttestation and verifyAttestationJWT functions, and deprecate clockSkewSec in favor of allowedSkewInSeconds for better naming consistency.
- fa29ab6: chore: drop node 18 support. Lowest supported Node.JS version is now 20.19 +
- ba93c72: it is now required to pass the `responseMode` object to the `resolveOpenid4vpAuthorizationRequest` method. The `responseMode` should contain a type indicating the expected response mode group (`direct_post`, `iae` or `dc_api`) along with response-mode specific parameters (e.g. `expectedOrigin`). This replaces the top-level `origin` parameter, and ensures only expected response modes are used within a context (since you are aware when calling the method whether you're in a DC/IAE or normal context).

### Patch Changes

- 6ebe36a: feat: use Oauth2ServerErrorResponseError for more errors for better error handling
- fa29ab6: feat: add support for Node 26
- ba93c72: fix: tigethened validation to disallow usage of `request_uri` in DC API request
- ba93c72: feat: add support for the new Interactive Authorization Endpoint from OpenID4VCI 1.1 draft to allow presentation during issuance. NOTE: this feature is experimental and not stable in OpenID4VCI yet, it may be changed in this library in an incompatible way in a patch release.
- 77339e2: fix: signed openid4vp requests without an `aud` field set now set the `aud` field to `https://self-issued.me/v2` according to OpenID4VP section 5.8
- Updated dependencies [4877518]
- Updated dependencies [6d35a38]
- Updated dependencies [fa29ab6]
- Updated dependencies [ba93c72]
- Updated dependencies [675b5b2]
- Updated dependencies [fa29ab6]
- Updated dependencies [3fb55be]
- Updated dependencies [1a8372b]
  - @openid4vc/oauth2@0.5.0
  - @openid4vc/utils@0.5.0

## 0.4.5

### Patch Changes

- Updated dependencies [9c0ac58]
- Updated dependencies [4fb7574]
  - @openid4vc/oauth2@0.4.5
  - @openid4vc/utils@0.4.5

## 0.4.4

### Patch Changes

- 3f3cfe7: chore: better zod errors with more detail of nested errors
- Updated dependencies [0bf46b7]
- Updated dependencies [3f3cfe7]
- Updated dependencies [3f3cfe7]
  - @openid4vc/oauth2@0.4.4
  - @openid4vc/utils@0.4.4

## 0.4.3

### Patch Changes

- @openid4vc/oauth2@0.4.3
- @openid4vc/utils@0.4.3

## 0.4.2

### Patch Changes

- f07e928: fix: actually pass `additionalJwtPayload` in openid4vp authorization request. Before in `createOpenid4vpAuthorizationRequest`, if `jar.additionalJwtPayload.aud` was undefined, the `additionalJwtPayload` was never passed the payload from the options.
- Updated dependencies [05af867]
  - @openid4vc/utils@0.4.2
  - @openid4vc/oauth2@0.4.2

## 0.4.1

### Patch Changes

- @openid4vc/oauth2@0.4.1
- @openid4vc/utils@0.4.1

## 0.4.0

### Minor Changes

- dfa7819: Remove support for the CommonJS/CJS syntax. Since React Native bundles your code, the update to ESM should not cause issues. In addition all latest minor releases of Node 20+ support requiring ESM modules. This means that even if you project is still a CommonJS project, it can now depend on ESM modules. For this reason oid4vc-ts is now fully an ESM module.

### Patch Changes

- Updated dependencies [dfa7819]
  - @openid4vc/oauth2@0.4.0
  - @openid4vc/utils@0.4.0

## 0.3.0

### Minor Changes

- edd7464: update the parsed dcql vp_token presentation result to always return an array of presentations
- 7904088: feat: support multi-presentation submission for transaction data (dcql multiple feature)
- 16e5b1c: feat: add support for `x509_hash` client id scheme.

  With support for this new client id scheme the `hash` callback is now required in the `Openid4vpClient`, and the `validateOpenid4vpClientId` method is now asynchronous.

- 1b5e003: feat: initial version of openid4vp
- fccae5c: chore: update to zod 4. Although the public API has not changed, it does impact the error messages and some of the error structures
- 06c016f: apu and apv in JWE encryptor are now base64 encoded values, to align with JOSE
- 06db16a: feat: add support for JAR in pushed authorization requests.

  NOTE: the `parsePushedAuthorizationRequest` now optionally returns an `authorizationRequestJwt` parameter. You MUST pass this to the `verifyPushedAuthorizationResponse` method to ensure the JWT is verified.

- 16e5b1c: refactor: client id scheme to client id prefix.

  All parameters have been changed to use prefix, so .e.g. `scheme` has become `prefix`. Only the parameters referring to the legacy separate `client_id_scheme` are still called scheme.

- 16e5b1c: feat: support the new `origin:` client id prefix in addition to `web-origin:` for the DC API.

  NOTE that for unsigned requests over the DC API, the `client_id` should be omitted, and you need to calculate the effective client id. Up to draft 25 this was `web-origin:<origin>` and after draft 25 it's `origin:<origin>`. It's not always possible to detect which prefix needs to be used, so if you're a verifier that wants to support both draft versions with the DC API, make sure to allow both prefixes for the session binding of presentations.

- 16e5b1c: add support for response encryption without leveraging JARM.

  Both the JARM-based response encryption, and the new OID4VP-based response encryption methods are supported. Both methods are used to determine which alg and enc values to use, and you should provide the same `jarm` configuration options. Once support for pre-1.0 drafts will be removed, the JARM options will also be replaced with a more OID4VP aligned API.

- 16e5b1c: feat: add support for draft 27 vp_formats_supported
- f798259: refactor: change the jwt signer method 'trustChain' to 'federation' and make 'trustChain' variable optional.
- 16e5b1c: feat: add support for the new `decentralized_identifier` and `openid_federation` client id schemes.

  The client information is also updated to return the `decentralized_identifier` and `openid_federation` scheme. The `effective` client is the value that should be used for comparison.

- edd7464: feat: update openid4vp to 1.0 final.

  The `version` returned in the `resolveOpenid4vpAuthorizationRequest` now returns `100` instead of `29` for the 1.0 final version of OpenID4VP.

### Patch Changes

- 0d8a658: Added `verifier_attestations` to DC Api type
- 8ca38b5: Fixes the response_uri check against the client identifier.
- 16e5b1c: feat: support verifier_attestation in addition to verifier_info
- 0fffe73: feat: return decryption jwk in verified jarm response
- 16e5b1c: feat: correctly extract jwk from jarm kid if defined
- c29dd5a: fix: entry file in package.json for cjs to point to the correct file extension
- 16e5b1c: deprecate the `x509_san_uri` client id scheme for draft 25+
- 919ef7c: fix: check whether client id identifier matches redirect_uri/resposne_uri when client id prefix is redirect_uri
- 16e5b1c: feat: add support for client_id_prefixes in addition to client_id_schemes
- 04db7c2: fix: set the effective client id to start with `web-origin:` for pre draft 25 authorization requests
- 4fd875d: Retain the `.passthrough()` in the Zod common credential configuration's for correct typing.
- 5abf3aa: feat: add method to calculate x509_hash
- 1e6b8c4: Fixes the parsing of the deferred credential response.
- 1a64f80: fix: allow string for expires_in when parsing openid4vp response payload to account for response submitted as url encoded
- 2e0249b: Exposed types and schema for verifier attestations
- 971f885: fix: export JarmMode enum
- 16e5b1c: feat: add `version` to the `resolveOpenid4vpAuthorizationRequest` return value, indicating the highest supported draft version for the authorization request
- 1c57f07: feat: allow providing custom JARM encryption jwk
- e1bd4e8: - Added `verifier_attestations` parsing
- 158fa8c: feat: support node 22 and 24
- 3b9b88a: fix: create fetch wrapper that always calls toString on URLSearchParams as React Native does not encode this correctly while Node.JS does
- 1ba4a59: Add support for parsing and verifying array 'aud' in JWTs.
- Updated dependencies [70b9740]
- Updated dependencies [fccae5c]
- Updated dependencies [06c016f]
- Updated dependencies [06db16a]
- Updated dependencies [08dbc00]
- Updated dependencies [a70c87b]
- Updated dependencies [5b69ca4]
- Updated dependencies [e206509]
- Updated dependencies [2cc4e31]
- Updated dependencies [e206509]
- Updated dependencies [70b9740]
- Updated dependencies [c29dd5a]
- Updated dependencies [70b9740]
- Updated dependencies [c8ce780]
- Updated dependencies [26451d7]
- Updated dependencies [e9483ca]
- Updated dependencies [c2c3499]
- Updated dependencies [f798259]
- Updated dependencies [9bf578f]
- Updated dependencies [158fa8c]
- Updated dependencies [d9b8118]
- Updated dependencies [c23c86f]
- Updated dependencies [4d1bfd7]
- Updated dependencies [3b9b88a]
- Updated dependencies [ef05cf9]
- Updated dependencies [1ba4a59]
- Updated dependencies [80d0ec1]
- Updated dependencies [1ad09cf]
  - @openid4vc/oauth2@0.3.0
  - @openid4vc/utils@0.3.0
