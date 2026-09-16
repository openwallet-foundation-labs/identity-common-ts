---
'@owf/mdoc': minor
---

Handle versions as ISO/IEC 18013-5 8.1 defines them, where an unknown minor version must not cause an error:

- A mobile security object with any `1.x` version is accepted. Before, only `1.0` was.
- `DeviceResponse.verify` reports a FAILED `Device Response must have a supported version` check for a version other than `1.x`, instead of only checking that there is a version.
- `Holder.verifyDeviceRequest` and `IsoMdocDcApi.parseRequest` report a FAILED `Device Request must have a supported version` check for a version other than `1.x`.
