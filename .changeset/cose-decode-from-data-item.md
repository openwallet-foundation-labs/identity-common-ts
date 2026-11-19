---
"@owf/cose": patch
---

`CborStructure.decode` decodes bytes wrapped in tag 24 with `fromDataItem`, so a subclass that overrides `fromDataItem` also sees the data item when it is decoded from bytes. The decoded structure and the errors are the same as before.
