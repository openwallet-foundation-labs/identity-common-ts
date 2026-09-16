---
'@owf/mdoc': minor
---

Embedded structures that are signed, MACed or hashed (`ItemsRequestBytes`, `DeviceNameSpacesBytes`, `DeviceEngagementBytes`, `EReaderKeyBytes`, `IssuerSignedItemBytes`) are now used with the bytes they were received as, as ISO/IEC 18013-5 8.1 requires, instead of being re-encoded. This fixes reader auth and device auth verification for implementations that encode CBOR differently.

These structures now build on the new `OriginalBytesCborStructure`, which keeps the decoded bytes as `originalBytes` until the structure is modified. Setting or deleting a map entry drops them automatically; call `markModified()` after changing a nested value. `IssuerSignedItem.originalPayloadBytes` is deprecated in favour of `originalBytes`.
