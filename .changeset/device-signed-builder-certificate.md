---
'@owf/mdoc': minor
---

Remove the `certificate` option of `DeviceSignedBuilder.sign` and `DeviceSignedBuilder.tag`. The device signature and device MAC of ISO/IEC 18013-5 9.1.3 are verified with the device key in the `deviceKeyInfo` of the MSO, so an `x5chain` header on the device auth has no meaning. The builder no longer adds one, like `DeviceResponse.createWithDeviceRequest` already did.
