---
"@owf/mdoc": patch
---

Read a `status` of `null` in the MSO as absent. ISO/IEC 18013-5 does not allow `null` there, but Apple Wallet's developer mDLs send it, which failed with `Error decoding Status: Expected map, received null`.
