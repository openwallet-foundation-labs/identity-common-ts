# @openid4vc/oauth2

## 0.10.0

### Minor Changes

- c3e5919: `verifyClientAttestationJwt` and `verifyKeyAttestationJwt` reject an attestation signed with a `jwk` signer. This also applies to `Oauth2AuthorizationServer.verifyClientAttestation`, the verification of authorization, pushed authorization and access token requests, `Openid4vciIssuer.verifyWalletAttestation`, and the issuer's verification of `jwt` and `attestation` proofs. The signer was taken from the attestation's own header, and `verifyJws` has to accept such keys for DPoP, PoP and proof JWTs, so a client could attest itself and a wallet could attest its own keys, for example to meet `key_attestations_required` (OpenID4VCI 1.0 Appendix D).
  
  An attestation signed with a `did` signer is still passed to `verifyJws`, which must check that the DID belongs to an attester it trusts. Resolving the DID is not enough: anyone can create a did:jwk or did:key, or host a did:web.
  
  **Breaking:** the attester must be identified by `x5c`, a federation `trust_chain`, a DID, or another `kid` that `verifyJws` resolves, and `verifyJws` decides whether it trusts it, for example by validating the `x5c` chain or by checking the DID against a list of trusted attesters. Sign attestations with one of these signers instead of a `jwk` header.
- 0060df2: **Breaking:** `Oauth2Error`, `Openid4vciError` and `Openid4vcBaseError` extend `IdentityError` of `@owf/identity-common`. Their `name` is their class name. `Oauth2Error` and `Openid4vciError` no longer append the message of their `cause`.
- 0060df2: **Breaking:** `Oauth2JwtParseError` and `Oauth2JwtVerificationError` are removed. Catch the `@owf/jose` errors that `@openid4vc/oauth2` exports: `JoseParseError`, `JoseVerificationError` and its subclasses, and `JoseValidationError` for a header or claim that does not validate, with issue codes such as `invalid_typ`, `expired` or `claim_value_mismatch`. They don't extend `Oauth2Error`, so catch `IdentityError` to handle both.
- 0060df2: Every JWT verification takes `now` and `allowedSkewInSeconds` (30 seconds by default), and `Oauth2ResourceServer`, `Openid4vciIssuer`, `Openid4vciClient`, `Openid4vpClient` and `Openid4vpVerifier` take a default `allowedSkewInSeconds`. Key attestations and JAR request objects are verified at the `now` passed in.
  
  DPoP proofs: `maxProofAgeSeconds` allows the skew, an `iat` in the future is always rejected, `assertJtiUniqueness` runs after the signature check, and the `JoseValidationError` of a failed claim is the `cause` of the error response.
  
  A `JoseInvalidArgumentError`, e.g. for a negative skew, is thrown as is instead of as an error response. An expired OpenID4VP request object gives `invalid_request_object`.
  
  A `typ` is accepted in any casing and with the `application/` prefix (RFC 7515 Section 4.1.9). Compare it with `isJwtTyp` of `@owf/identity-common`.
- 0060df2: Schema issues have the codes of `@owf/identity-common`, such as `missing_value` or `invalid_format`, instead of `invalid_value`.
  
  **Breaking:** values the specifications don't allow to be empty are rejected when empty, e.g. `client_id`, `nonce`, `c_nonce`, `pre-authorized_code`, `vct`, `access_token` and `jti`. `dpop_signing_alg_values_supported` rejects `none` (RFC 9449 Section 4.2).
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
- 5fff735: Media types are compared with `isMediaType` and JOSE `typ` values with `isJwtTyp`, both from `@owf/identity-common`. New: `CommonMediaTypes` of `@owf/identity-common`, the media types that are not specific to one specification, and `Oauth2MediaTypes` of `@openid4vc/oauth2`, with the JAR request object media type. JARM accepts its `Content-Type` in any casing. A Key Binding JWT and a registration certificate accept their `typ` in any casing and with the `application/` prefix (RFC 7515 Section 4.1.9).
  
  **Breaking:** `isContentType` and `isResponseContentType` are removed from `@openid4vc/utils`. Replace `isContentType(contentType, value)` with `isMediaType(value, contentType)` and `isResponseContentType(contentType, response)` with `isMediaType(response.headers.get('Content-Type'), contentType)`. `MediaTypes` is renamed to `StatusListMediaTypes` in `@owf/token-status-list` and to `MdocMediaTypes` in `@owf/mdoc`. `ContentType` is removed from `@openid4vc/utils`: use `CommonMediaTypes`, and `Oauth2MediaTypes.AuthorizationRequestJwt` for `ContentType.OauthAuthorizationRequestJwt`. The `expectedContentType` of a `ZodFetcher` is a `string`.

### Patch Changes

- 0060df2: `clientAuthenticationClientSecretBasic` form-urlencodes the client id and secret and encodes them with base64 instead of base64url (RFC 6749 Section 2.3.1, RFC 7617).
- 25c7506: Proofs of possession are only accepted for a limited time, so a captured one can no longer be replayed indefinitely:
  
  - `verifyDpopJwt`, and the DPoP checks of `verifyAuthorizationRequest`, `verifyPushedAuthorizationRequest`, the access token request verification and `verifyResourceRequest`, reject a DPoP proof whose `iat` is more than 300 seconds ago unless `maxProofAgeSeconds` allows more (RFC 9449 Section 11.1). Before, a proof without `maxProofAgeSeconds` was valid forever. `expectedNonce` is now accepted by all of them, so a server can require its nonce for authorization and resource requests too (RFC 9449 Section 8).
  - `verifyClientAttestationPopJwt` requires the `iat` of a client attestation PoP (draft-ietf-oauth-attestation-based-client-auth-09 Section 5.2) and rejects one older than 300 seconds. `verifyClientAttestation` and the client attestation options of the authorization and access token request verification accept `expectedChallenge`, so a server can enforce the challenge it issued (Section 6).
  - `verifyCredentialRequestJwtProof` rejects a `jwt` proof whose `iat` is more than 300 seconds ago (OpenID4VCI 1.0 Appendix F.4).
- Updated dependencies [90614a9]
- Updated dependencies [0060df2]
- Updated dependencies [ebd0b4b]
- Updated dependencies [ec2ed51]
- Updated dependencies [5d665bb]
- Updated dependencies [946d9af]
- Updated dependencies [0060df2]
- Updated dependencies [755e2eb]
- Updated dependencies [0060df2]
- Updated dependencies [ec2ed51]
- Updated dependencies [cb487f1]
- Updated dependencies [5fff735]
- Updated dependencies [04cfd04]
  - @openid4vc/utils@0.10.0
  - @owf/identity-common@0.8.0
  - @owf/jose@0.8.0

## 0.9.2

### Patch Changes

- 410d45a: `zJarAuthorizationRequest` now requires `request` or `request_uri`. Before, it matched any object. An unsigned request that failed the regular schema was accepted without validation in `resolveOpenid4vpAuthorizationRequest`, `parseOpenid4vpAuthorizationRequest`, `parsePushedAuthorizationRequest` and `parseInteractiveAuthorizationRequest`. For OpenID4VP, this skipped the https check on `response_uri`, so a wallet could send the presentation over plain http.
- @openid4vc/utils@0.9.2

## 0.9.1

### Patch Changes

- 33576aa: Export `RetrieveAccessTokenReturn` so consumers can name the return type of access token retrieval methods.
- b74d901: Add `Openid4vciIssuer.parseNotificationRequest` to validate a Notification Request at the issuer's notification endpoint. An invalid request throws an `Oauth2ServerErrorResponseError` with the new `Oauth2ErrorCodes.InvalidNotificationRequest`. `Oauth2ErrorCodes.InvalidNotificationId` is added for unknown notification ids.
- @openid4vc/utils@0.9.1

## 0.9.0

### Patch Changes

- fa1ce42: `verifyResourceRequest` now rejects an opaque access token when token introspection reports it as inactive. Before, a response with `active: false` was accepted, so revoked, expired or unknown tokens passed verification.
- 34bd5c9: Requests made with `createZodFetcher` now send the expected content types as the `Accept` header, unless the request already sets one. The first content type is preferred, and later ones get decreasing `q` values. Before, the expected content types were only checked against the response `Content-Type`.
- Updated dependencies [bf9b7c8]
- Updated dependencies [34bd5c9]
  - @openid4vc/utils@0.9.0

## 0.8.2

### Patch Changes

- @openid4vc/utils@0.8.2

## 0.8.1

### Patch Changes

- 4ae057c: Accept the JWT `typ` header in its full media type form (`application/openid4vci-proof+jwt`) and in any casing, as RFC 7515 Section 4.1.9 requires. This applies to client attestations, client attestation PoPs, JAR request objects, access tokens, credential request proofs, key attestations and signed credential issuer metadata. Created JWTs still use the short lowercase form. `@openid4vc/utils` adds `isJwtTyp(value, typ)` for the check, and `zTyp(typ)`, a schema that uses it. It keeps `typ` as sent, so the `typ` of the parsed header types is now `string`.
- Updated dependencies [4ae057c]
  - @openid4vc/utils@0.8.1

## 0.8.0

### Minor Changes

- 2538f35: Bind authorization sessions and refresh tokens to the client instance key. `verifyClientAttestationJwt` now returns `confirmationJwkThumbprint`, the thumbprint of the `cnf` key of the client attestation, and accepts `expectedConfirmationJwkThumbprint` and `expectedClientId` to reject a client attestation for another key or client id. Authorization requests, token requests and `Oauth2AuthorizationServer.verifyClientAttestation` accept the same options. Pass `clientAttestation.clientAttestation.confirmationJwkThumbprint` from an earlier request as `clientAttestation.expectedConfirmationJwkThumbprint` in later requests, as required for refresh tokens by draft-ietf-oauth-attestation-based-client-auth section 10.3. A client attestation is required when it is set.
  
  `verifyClientAttestationJwt` now requires the `hash` callback.

### Patch Changes

- 3b10167: Fix the `cnf` claim of a DPoP-bound access token created by `createAccessTokenJwt` on Hermes (React Native). Hermes compilers before 250829098.0.12 (facebook/hermes#2010) return the last property value instead of the object when an object literal in a ternary branch contains an `await`, so the token had `cnf` set to the thumbprint string instead of `{ jkt: <thumbprint> }`.
- 03a2040: Security fix: `encodeWwwAuthenticateHeader`, and so `Oauth2ResourceUnauthorizedError.toHeaderValue()`, always returns a valid header value. Control and non-ASCII characters are replaced with a space and an `error_description` longer than 500 characters is truncated, so a value taken from the request can no longer inject a header or make setting the header throw.
  
  `parseWwwAuthenticateHeader`, and so `Oauth2ResourceUnauthorizedError.fromHeaderValue()`, unescapes every escaped character in a quoted string (`\\` becomes `\`), not only an escaped quote.
- Updated dependencies [03a2040]
  - @openid4vc/utils@0.8.0

## 0.7.0

### Minor Changes

- 222ed67: Unify the clock skew option name to `allowedSkewInSeconds` and add a server-level default.
  
  - **Breaking:** the DPoP `allowedClockSkewSeconds` option is renamed to `allowedSkewInSeconds`. This applies to `verifyDpopJwt` and to the `dpop` options of `verifyPushedAuthorizationRequest`, `verifyAuthorizationChallengeRequest`, the `verify*AccessTokenRequest` methods and `verifyResourceRequest`.
  - Add `allowedSkewInSeconds` to `Oauth2AuthorizationServer` as the default allowed clock skew for DPoP and client attestation verification in `verifyPushedAuthorizationRequest`, `verifyAuthorizationChallengeRequest`, the `verify*AccessTokenRequest` methods, `verifyDpopJwt` and `verifyClientAttestation`. A per-call `allowedSkewInSeconds` in the DPoP or client attestation options overrides the server default, including `0`.
  - The `verify*AccessTokenRequest` methods now pass `now` to DPoP proof verification, so the DPoP `iat` checks use the provided time instead of the current time.

### Patch Changes

- 1beaa04: Normalize the `htu` claim of a DPoP proof the same way as the request URL before comparing them, so query and fragment are ignored (RFC 9449 §4.3) and an uppercase host or explicit default port no longer cause a mismatch (RFC 3986 §6.2.2, §6.2.3). `zHttpsUrl` now accepts the URL scheme case-insensitively (RFC 3986 §3.1).
- c0107e4: Allow configuring clock skew for client attestation verification on the authorization server.
  
  - Add optional `allowedSkewInSeconds` (default `0`) to the `clientAttestation` options of `verifyPushedAuthorizationRequest`, `verifyAuthorizationChallengeRequest` and the `verify*AccessTokenRequest` methods. It is applied to the `nbf` and `exp` checks of both the Client Attestation JWT and the Client Attestation PoP JWT, including the DPoP-bound `attest_jwt_client_auth_dpop` method.
  - `verifyClientAttestationJwt` now honours its `allowedSkewInSeconds` option, which was previously ignored.
- Updated dependencies [1beaa04]
- Updated dependencies [5d2179b]
  - @openid4vc/utils@0.7.0

## 0.6.0

### Minor Changes

- 019f316: BREAKING: `parseJarRequest` and `validateJarRequestParams` no longer allow a `request_uri` by default. The `allowRequestUri` option now defaults to `false`, so a JAR request passed by reference is rejected with an `invalid_request_object` error (and `parseJarRequest` won't fetch it) unless you explicitly pass `allowRequestUri: true`.

### Patch Changes

- 0d30e2d: Match the `Authorization` header authentication scheme case-insensitively in `verifyResourceRequest`, as required by RFC 9110 §11.1. A request using e.g. `dpOp` or `bearer` is now accepted, and the scheme is resolved to its canonical form (`DPoP` / `Bearer`) for the rest of the verification.
- f3efa25: Report a client attestation or client attestation PoP JWT that fails schema validation (e.g. a missing `sub`, `exp`, `cnf.jwk` or `jti` claim) as `invalid_client` with status `401`, consistent with signature and expiry failures. Previously the `ValidationError` was reported as a `500` `server_error` by `verifyClientAttestation`, and was not mapped to an OAuth2 error at all for the `attest_jwt_client_auth_dpop` method.
- 83123e8: Respond with `invalid_grant` instead of `invalid_request` when the `code_verifier` is missing from an access token request for an authorization code bound to a PKCE code challenge, as required by RFC 7636 §4.6.
- 2a28c82: Reject a pushed authorization request or interactive authorization request containing a `request_uri` parameter with an `invalid_request` error, instead of fetching the `request_uri`.
- 83123e8: Reject an access token request with `invalid_grant` when it contains a `code_verifier` but no `pkce` options are passed to the verify function (the grant is not bound to a code challenge). This prevents a PKCE downgrade attack as described in RFC 9700 §4.8.2, where a code obtained without PKCE is injected into the flow of a client that does use PKCE.
- 18f267c: Omit absent `error`, `error_description` and `scope` parameters from the `WWW-Authenticate` header produced by `Oauth2ResourceUnauthorizedError.toHeaderValue()`. Previously they were emitted as bare parameter names (e.g. `Bearer error, error_description, scope`), which is not a valid challenge per RFC 9110 §11.6.1. `encodeWwwAuthenticateHeader` now skips payload entries with an `undefined` value, while `null` values are still encoded as bare parameter names.
- Updated dependencies [18f267c]
  - @openid4vc/utils@0.6.0

## 0.5.6

### Patch Changes

- 410dae1: Add configurable DPoP proof freshness and replay validation hooks.
  
  - Add optional `maxProofAgeSeconds` and `allowedClockSkewSeconds` checks in DPoP verification.
  - Add optional `assertJtiUniqueness` callback for replay protection.
  - Thread these DPoP verification options through access-token, authorization-request, and resource-request verification APIs.
  - Add tests for DPoP validation edge cases and `use_dpop_nonce` retry behavior with fresh proofs.
- edfc2b5: Move the `@openid4vc/*` packages from the `oid4vc-ts` repository into `identity-common-ts`. The `@openid4vc/*` packages keep being versioned together, separately from the other packages in this repository.
  
  The packages stay ESM-only. Type declarations are now exposed through the `types` export condition, and `main` points to the ESM build. `require('@openid4vc/oauth2')` loads the ESM build, which needs a Node.js version that supports `require(esm)` (Node.js 20.19 and later, or 22.12 and later).
  
  The builds no longer include copies of code from other `@openid4vc/*` packages. `@openid4vc/oauth2` bundled its own copy of `ValidationError`, so `instanceof ValidationError` checks against the class exported by `@openid4vc/utils` failed for some errors thrown by `@openid4vc/oauth2`. `@openid4vc/openid4vci` and `@openid4vc/openid4vp` bundled copies of `zOauth2ErrorResponse` and `addSecondsToDate`. `@openid4vc/oauth2` now exports the `VerifyClientAttestationOptions` type.
- Updated dependencies [edfc2b5]
  - @openid4vc/utils@0.5.6

## 0.5.5

### Patch Changes

- 6060c2d: Add `getAuthorizationServerMetadata` and `getJwks` callbacks to the `CallbackContext`, allowing authorization server metadata and JWK Sets to be resolved without performing a request.
  
  This makes it possible to avoid network requests for metadata and keys that the caller already has (for example an authorization server hosted by the same application, which would otherwise result in an HTTP request to itself when verifying an access token it issued), and to serve metadata and keys from a cache.
  
  Both callbacks are optional. If not provided, or if they return `undefined`, the metadata and JWK Sets are fetched over HTTP as before. `getAuthorizationServerMetadata` can additionally return `null` to indicate the metadata definitively does not exist, so it is not requested again.
  
  Values returned by the callbacks are validated exactly like fetched values: a JWK Set is parsed with the JWK Set schema, and authorization server metadata is parsed with the authorization server metadata schema and must have an `issuer` matching the requested issuer.
  
  The second parameter of the exported `fetchJwks` and `fetchAuthorizationServerMetadata` functions now also accepts an object with `fetch` and the matching resolve callback, in addition to the `Fetch` implementation it accepted before.
- @openid4vc/utils@0.5.5

## 0.5.4

### Patch Changes

- 63aeaa9: Add support for the DPoP-bound `attest_jwt_client_auth_dpop` client authentication method (draft 09 §5.2): a new `clientAuthenticationClientAttestationJwtDpop` client-auth callback that emits a single DPoP proof doubling as the Client Attestation PoP (client instance key == DPoP key), plus authorization-server verification of the combined method (attestation JWT + DPoP proof with a mandatory `cnf` JWK to DPoP key match). The combined method is rejected when the authorization server advertises client authentication methods that do not include `attest_jwt_client_auth_dpop`.
  - @openid4vc/utils@0.5.4

## 0.5.3

### Patch Changes

- 9c4c66c: Add support for di_vp proofs in credential requests
- 6886ca5: Add `Oauth2Client.requestClientAttestationChallenge` to fetch a Client Attestation challenge from the authorization server's `challenge_endpoint`, and support the `use_attestation_challenge` reactive challenge retry (draft 09) so the challenge is automatically included in the Client Attestation PoP when the server requests one.
  - @openid4vc/utils@0.5.3

## 0.5.2

### Patch Changes

- 33adaf0: Align wallet (client) attestation with draft 09 of OAuth 2.0 Attestation-Based Client Authentication.

  - Client Attestation and Client Attestation PoP JWTs no longer emit the `iss` claim (removed in draft 08). Verification still accepts legacy JWTs that include `iss`.
  - The Client Attestation PoP JWT uses the `challenge` claim (renamed from `nonce` in draft 06) and no longer includes `exp` (removed in draft 06). Verification accepts either `challenge` or the legacy `nonce`. The `nonce`/`expectedNonce` options are deprecated aliases for `challenge`/`expectedChallenge`.
  - Added authorization server metadata parameters `client_attestation_signing_alg_values_supported` and `client_attestation_pop_signing_alg_values_supported` (draft 07), the `challenge_endpoint` parameter, the `attest_jwt_client_auth_dpop` authentication method, and the `OAuth-Client-Attestation-Challenge` header (draft 09).
  - `verifyClientAttestationPopJwt` accepts an `expectedAudience` option so a resource server can verify a PoP JWT bound to its own identifier (draft 09).
  - @openid4vc/utils@0.5.2

## 0.5.1

### Patch Changes

- @openid4vc/utils@0.5.1

## 0.5.0

### Minor Changes

- 675b5b2: Pass allowedSkewInSeconds to verifyClientAttestation and verifyAttestationJWT functions, and deprecate clockSkewSec in favor of allowedSkewInSeconds for better naming consistency.
- fa29ab6: chore: drop node 18 support. Lowest supported Node.JS version is now 20.19 +
- 1a8372b: Parses and Verify grant types against grant_types_supported.
  This can cause issues if the authorization server does not have the
  correct grant_types_supported configured correctly.

### Patch Changes

- 4877518: fix: make an exception for openid4vci-proof+jwt jwt typ where iss value does not match the did in the jwt proof header
- 6d35a38: feat: add support for request & reponse encryption
- fa29ab6: feat: add support for Node 26
- ba93c72: feat: add support for the new Interactive Authorization Endpoint from OpenID4VCI 1.1 draft to allow presentation during issuance. NOTE: this feature is experimental and not stable in OpenID4VCI yet, it may be changed in this library in an incompatible way in a patch release.
- 3fb55be: Remove exp field from wallet attestation JWT payload schema
  Export CreateCredentialResponseOptions type
- Updated dependencies [fa29ab6]
- Updated dependencies [fa29ab6]
  - @openid4vc/utils@0.5.0

## 0.4.5

### Patch Changes

- 9c0ac58: fix: allow non-integer (decimal) numbers for JWT claims (iat/nbf/exp)
- 4fb7574: feat: support retrieving client credentials access token
- Updated dependencies [9c0ac58]
  - @openid4vc/utils@0.4.5

## 0.4.4

### Patch Changes

- 0bf46b7: feat: add support for RFC 9207 OAuth 2.0 Authorization Server Issuer Identification and add methods to the Oauth2Client and Openid4vciClient to parse and verify an authorization response. To meet HAIP requirements you should set `authorization_response_iss_parameter_supported` to true in your authorization server, and in the wallet you should use the new `Openid4vciClient.parseAndVerifyAuthorizationResponseRedirectUrl` to parse and verify the authorization response. The verification method only verifies against the authorization server metadata, while HAIP/FAPI require the value to ALWAYS be present. In the future a method will be added that verifies if the authorization server metadata is aligned with the requirements of HAIP. This way the verification methods can stay simpler, and verify based on the authorization server metadata.
- 3f3cfe7: fix: throw error in well known metadata retrieval if an error was thrown during first try
- 3f3cfe7: chore: better zod errors with more detail of nested errors
- Updated dependencies [3f3cfe7]
  - @openid4vc/utils@0.4.4

## 0.4.3

### Patch Changes

- @openid4vc/utils@0.4.3

## 0.4.2

### Patch Changes

- Updated dependencies [05af867]
  - @openid4vc/utils@0.4.2

## 0.4.1

### Patch Changes

- @openid4vc/utils@0.4.1

## 0.4.0

### Minor Changes

- dfa7819: Remove support for the CommonJS/CJS syntax. Since React Native bundles your code, the update to ESM should not cause issues. In addition all latest minor releases of Node 20+ support requiring ESM modules. This means that even if you project is still a CommonJS project, it can now depend on ESM modules. For this reason oid4vc-ts is now fully an ESM module.

### Patch Changes

- Updated dependencies [dfa7819]
  - @openid4vc/utils@0.4.0

## 0.3.0

### Minor Changes

- 70b9740: Add support for OpenID4VCI draft 15. It also includes improved support for client (wallet) attestations, and better support for server side verification.

  Due to the changes between Draft 14 and Draft 15 and it's up to the caller of this library to handle the difference between the versions. Draft 11 is still supported based on Draft 14 syntax (and thus will be automatically converted).

- fccae5c: chore: update to zod 4. Although the public API has not changed, it does impact the error messages and some of the error structures
- 06c016f: apu and apv in JWE encryptor are now base64 encoded values, to align with JOSE
- 06db16a: feat: add support for JAR in pushed authorization requests.

  NOTE: the `parsePushedAuthorizationRequest` now optionally returns an `authorizationRequestJwt` parameter. You MUST pass this to the `verifyPushedAuthorizationResponse` method to ensure the JWT is verified.

- 70b9740: fix typo in param from authorizationServerMetata to authorizationServerMetadata
- 70b9740: replace the `dpopJwk` return value with `dpop` object with `jwk` key. It now also returns the `jwkThumbprint`
- 26451d7: Before this PR, all packages used Valibot for data validation.
  We have now fully transitioned to Zod. This introduces obvious breaking changes for some packages that re-exported Valibot types or schemas for example.
- f798259: refactor: change the jwt signer method 'trustChain' to 'federation' and make 'trustChain' variable optional.
- c23c86f: add support for sha-384, sha-512, rename SHA-256 to sha-256 to align with IANA hash algorithm names (<https://www.iana.org/assignments/named-information/named-information.xhtml>)

### Patch Changes

- 08dbc00: Add grant_types_supported to the authorization server metadata.
- a70c87b: fix: make key_ops array of strings instead of string in jwk
- 5b69ca4: Fixes miscellaneous typos and adds code to the authorization request.
- e206509: Add support for deferred credential issuance and Draft 16 of the OpenID for Verifiable Credential Issuance.
- 2cc4e31: Add function to parse authorization response redirect URLs.
- e206509: Fix a myriad of typos across errors, comments, and variable names.
- c29dd5a: fix: entry file in package.json for cjs to point to the correct file extension
- c8ce780: fix: path where oauth2 authorization server metadata is retrieved from.

  For OAuth you need to put `.well-known/oauth-authorization-server` between the origin and path (so `https://funke.animo.id/provider` becomes `https://funke.animo.id/.well-known/oauth-authorization-server/provider`). We were putting the well known path after the full issuer url.

  It will now first check the correct path, and fall back to the invalid path.

- e9483ca: Add support for parsing and verifying an ID Token JWT according to the OpenID Connect specification.

  Exports some other utilities.

- c2c3499: Add authorization server support for refresh tokens, as well as verifying requests with refresh token grants.
- 9bf578f: fix: loosen the allowed content type for JWK Set to include application/json
- 158fa8c: feat: support node 22 and 24
- d9b8118: feat: add `kid` to the JwtSigner interface
- 4d1bfd7: Add function to parse a pushed authorization request uri.
- 3b9b88a: fix: create fetch wrapper that always calls toString on URLSearchParams as React Native does not encode this correctly while Node.JS does
- ef05cf9: Correctly passes the state down to the authentication challenge request.
- 1ba4a59: Add support for parsing and verifying array 'aud' in JWTs.
- 80d0ec1: Send redirect_uri along in the authorization challenge endpoint, allowing the server to use it when defaulting to a PAR request.
- 1ad09cf: Pass state onto the authorization request URL.
- Updated dependencies [70b9740]
- Updated dependencies [fccae5c]
- Updated dependencies [70b9740]
- Updated dependencies [c29dd5a]
- Updated dependencies [26451d7]
- Updated dependencies [158fa8c]
- Updated dependencies [3b9b88a]
  - @openid4vc/utils@0.3.0

## 0.2.0

### Minor Changes

- 0f60387: feat: add client attestations
- 3f6d360: change order of fetching authorization server metadata. First `oauth-authorization-server` metadata is fetched now. If that returns a 404, the `openid-configuration` will be fetched.

### Patch Changes

- @openid4vc/utils@0.2.0

## 0.1.4

### Patch Changes

- 12a517a: feat: add refresh_token grant type
  - @openid4vc/utils@0.1.4

## 0.1.3

### Patch Changes

- d4b9279: chore: create github release
- Updated dependencies [d4b9279]
  - @openid4vc/utils@0.1.3

## 0.1.2

### Patch Changes

- 1de27e5: chore: correct formatting for publishing
- Updated dependencies [1de27e5]
  - @openid4vc/utils@0.1.2

## 0.1.1

### Patch Changes

- 6434781: docs: add readme
- Updated dependencies [6434781]
  - @openid4vc/utils@0.1.1

## 0.1.0

### Minor Changes

- 71326c8: feat: initial release

### Patch Changes

- Updated dependencies [71326c8]
  - @openid4vc/utils@0.1.0
