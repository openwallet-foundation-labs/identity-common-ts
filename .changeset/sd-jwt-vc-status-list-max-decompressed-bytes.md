---
'@sd-jwt/sd-jwt-vc': minor
---

The new `maxStatusListDecompressedBytes` of `SdJwtVcConfig` limits the size the status list of a credential may inflate to, 16 MiB by default. `verify` and `safeVerify` reject a larger list, and read the status in the decompressed bytes of the list, so it takes no more memory than its decompressed size.

The default `statusListFetcher` fetches the status list with `fetchStatusList` of `@owf/token-status-list`, and rejects a response larger than the new `maxStatusListResponseBytes` of `SdJwtVcConfig`, 16 MiB by default. Before, it read a response of any size. Its timeout of 10 seconds now covers reading the body, and its errors are a `StatusListError` with the message of `fetchStatusList`, such as `Could not fetch status list, response status '500'` instead of `Error fetching status list: 500`.
