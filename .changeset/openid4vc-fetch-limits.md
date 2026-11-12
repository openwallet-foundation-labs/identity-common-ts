---
'@openid4vc/utils': minor
'@openid4vc/oauth2': minor
'@openid4vc/openid4vci': minor
'@openid4vc/openid4vp': minor
---

Every request reads its response within the new `fetchLimits` of `CallbackContext` (see `FetchLimits` of `@owf/identity-common`), 10 MiB per response by default. Before, a response of any size was read, also to put its body in an `InvalidFetchResponseError`. The `fetch` callback gets what is requested as its third argument, e.g. `{ type: 'accessToken' }`, `{ type: 'credential' }` or `{ type: 'jwks' }`, so it can apply its own policy per type. The functions that take a `fetch` option, such as `resolveCredentialOffer`, `requestNonce`, `fetchClientMetadata` and `fetchJarRequestObject`, take `fetchLimits` next to it, and `resourceRequest` takes the `type` of what it requests.

**Breaking:** `createFetcher(callbacks, type)` and `createZodFetcher(callbacks, type)` of `@openid4vc/utils` take the `fetch` and `fetchLimits` of the callbacks and the type of the request, instead of a `fetch`, and the fetch they return takes a `string` URL. `fetchWellKnownMetadata` of `@openid4vc/oauth2` requires the `type` option, `'authorizationServerMetadata'` or `'credentialIssuerMetadata'`. `Fetch` is the `FetchCallback` of `@owf/identity-common`, which the global `fetch` still satisfies.
