---
'@sd-jwt/sd-jwt-vc': minor
---

The new `maxStatusListDecompressedBytes` of `SdJwtVcConfig` limits the size the status list of a credential may inflate to, 16 MiB by default. `verify` and `safeVerify` reject a larger list, and read the status in the decompressed bytes of the list, so it takes no more memory than its decompressed size.
