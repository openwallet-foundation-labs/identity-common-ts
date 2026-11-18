---
'@owf/mdoc': minor
---

`Issuer.sign`, `IssuerSignedBuilder.sign`, `DeviceSignedBuilder.sign`, `DeviceSignedBuilder.tag`, `DeviceResponse.createWithDeviceRequest` and `Holder.createDeviceResponseForDeviceRequest` no longer write the `keyId` of the signing key as a `kid` header in the IssuerAuth, DeviceSignature or DeviceMac. ISO/IEC 18013-5 does not define a `kid` there. A reader identifies the issuer key by the `x5chain` and the device key by the MSO. A `keyId` that only the signer uses, such as the id of the key in a key management system, was sent to the reader.

**Breaking:** a reader that selected the key by `kid` must use the `x5chain` and the MSO instead. To still send a `kid`, create the `IssuerAuth`, `DeviceSignature` or `DeviceMac` with your own `UnprotectedHeaders`.
