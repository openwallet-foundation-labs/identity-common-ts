---
'@owf/token-status-list': patch
---

`StatusList.decompressStatusListFromBytes`, and through it `verifyStatusListJwt`, `decodeStatusListJwt` and a `StatusListCwt`, reject an `lst` in the gzip format or with bytes after the end of its ZLIB stream with an `invalid_status_list` issue. Token Status List draft 16 § 4.1 requires DEFLATE in the ZLIB format, but pako inflated a gzip stream as well, and ignored whatever followed the stream.
