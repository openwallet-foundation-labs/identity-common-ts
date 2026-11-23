---
'@owf/token-status-list': minor
---

`statusList` of a `StatusList` returns a copy of the statuses, typed `readonly number[]`. A status written to the returned array, as in `list.statusList[3] = 1`, did not set `isModified`, so a `StatusListCbor` or `StatusListCwt` kept and signed its old compressed list. The constructor also copies the array it is given.

Every `StatusList` now keeps its statuses in the byte array of Token Status List draft 16 § 4.1, also one created from an array. It takes `bitsPerStatus` bits per status, where the array took about 8 bytes.

**Breaking:** a write to the array of `statusList` no longer changes the list, and no longer compiles. Use `setStatus(index, value)`.
