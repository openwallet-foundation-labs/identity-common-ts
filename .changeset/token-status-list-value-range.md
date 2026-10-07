---
"@owf/token-status-list": patch
---

`StatusList` rejects status values that do not fit in `bitsPerStatus` bits instead of encoding them into the neighbouring entries. The constructor, `setStatus` and the encoder accept only integers from 0 to `2 ** bitsPerStatus - 1`, so for example a suspension (`2`) on a list with 1 bit per status now throws an `SLException`. Previously the constructor accepted `2 ** bitsPerStatus`, and negative or non-integer values were not checked at all.
