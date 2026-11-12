---
'@sd-jwt/sd-jwt-vc': minor
---

The new `maxStatusListDecompressedBytes` of `SdJwtVcConfig` limits the size the status list of a credential may inflate to, 16 MiB by default. `verify` and `safeVerify` reject a larger list, and read the status in the decompressed bytes of the list, so it takes no more memory than its decompressed size.

The default `statusListFetcher` fetches the status list with `fetchStatusList` of `@owf/token-status-list`, and rejects a response larger than 16 MiB, or the `statusList` limit of the new `fetchLimits` of `SdJwtVcConfig` (see `FetchLimits` of `@owf/identity-common`). Before, it read a response of any size. Its timeout of 10 seconds now covers reading the body, and its errors are a `StatusListError` with the message of `fetchStatusList`, such as `Could not fetch status list, response status '500'` instead of `Error fetching status list: 500`.

The default `vctFetcher` rejects a type metadata response larger than 1 MiB, or the `typeMetadata` limit of `fetchLimits`. Before, it read a response of any size.

Both default fetchers fetch with the new `fetch` of `SdJwtVcConfig`, the global `fetch` by default, which gets `{ type: 'statusList' }` or `{ type: 'typeMetadata' }` as its third argument.
