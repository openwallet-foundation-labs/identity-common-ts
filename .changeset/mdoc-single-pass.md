---
"@owf/mdoc": patch
---

Verifying and creating a device response does less repeated work.

- `IssuerAuth.mobileSecurityObject` is decoded and validated once per instance, and again when the payload is replaced. It returns the same `MobileSecurityObject` on every access, so a change to it is seen by later reads.
- `DeviceResponse.verify`, `DeviceResponse.createWithDeviceRequest` and `DeviceAuth.verify` decode a session transcript passed as bytes once, instead of once or twice per document.
- A built `IssuerSignedItem`, `DeviceNamespaces`, `ItemsRequest`, `DeviceRequestInfo` or `DeviceEngagement` keeps the bytes of its first `encode()`, so the bytes that are hashed or signed are the bytes that are sent. Changing an entry of the structure drops them. Call `markModified()` after changing a nested value in place, as for a decoded structure.
- Decoding one of these structures, or an `EReaderKey`, no longer decodes the CBOR twice.
