---
'@openid4vc/utils': patch
'@openid4vc/openid4vci': patch
'@openid4vc/openid4vp': patch
---

`InvalidFetchResponseError` no longer puts the response body into its message, and `createZodFetcher` throws it without quoting the body when a response is not valid JSON. The fetched URL can be chosen by whoever sent a request, such as a `credential_offer_uri`, and the message could return the first 1000 characters of an internal endpoint's response to them. The body stays available as `textResponse`.

`resolveCredentialOffer` only fetches a `credential_offer_uri` that is an https URL (OpenID4VCI 1.0 Section 4.1). `resolveOpenid4vpAuthorizationRequest` fetches the `client_metadata_uri` with `callbacks.fetch` instead of the global `fetch`, so a wallet that restricts the URLs it requests also restricts this one, and `zClientMetadata` only accepts an https `jwks_uri`. `zDataUrl` only accepts a string that starts with `data:`, so `logo_uri` and the display images of credential issuer metadata no longer accept, for example, an http URL with `data:` in its query.
