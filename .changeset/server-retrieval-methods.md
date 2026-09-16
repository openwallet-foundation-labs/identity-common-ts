---
'@owf/mdoc': minor
---

`DeviceEngagement.serverRetrievalMethods` is a single `ServerRetrievalMethod`, as ISO/IEC 18013-5 8.2.1.1 defines `ServerRetrievalMethods` as one map with optional `webApi` and `oidc` entries. Before, it was an array, so a device engagement with server retrieval methods could not be decoded. **Breaking:** pass a `ServerRetrievalMethod` instead of an array to `DeviceEngagement.create`.

`DeviceEngagement.create` also no longer throws for every device engagement.
