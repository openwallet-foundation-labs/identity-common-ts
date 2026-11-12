---
'@owf/token-status-list': minor
---

A decompressed `StatusList` reads and sets each status in its decompressed bytes (Token Status List draft 16 § 4.1), instead of expanding the list into an array of numbers. Reading a list of 4 MiB at 1 bit per status took about 250 MB and 2 seconds, and now takes the 4 MiB of the list. The array is built only when `statusList` is read.

The limit of a decompressed list is `maxDecompressedBytes`, 16 MiB by default, which is 2^27 statuses at 1 bit per status, or 2^24 at 8 bits. Token Status List draft 16 § 8.3 sets no maximum, so a signed list of about 1 MB can inflate to 1 GiB. Pass the option to `verifyStatusListJwt`, `decodeStatusListJwt`, `StatusList.decompressStatusListFromBytes`, `StatusListCwt.verify` and `verifyStatus`, and `StatusListCwtPayload.verifyStatus`. The new `getStatusList(options)` of `StatusListCwtPayload` and `StatusListCbor` reads the list with it.
