---
'@owf/mdoc': minor
---

A device MAC (ISO/IEC 18013-5 9.1.3.5) is created and verified with the new `crypto.deviceMac` callback of `MdocContext`, so the device key and the ephemeral reader key can stay in a key management system. It gets the `CoseKey` passed to the library, the public key of the other party, the HKDF salt and info, and the MAC_structure, and returns the HMAC-SHA256 tag. `DeviceMac.authenticateWithKeyAgreement` sets the tag with it.

**Breaking:** `MdocContext` no longer has `crypto.hdkf` and `cose.mac0`, so it takes no raw private keys. Move their key agreement, HKDF and HMAC into `crypto.deviceMac`. Without it, creating a device MAC throws a `DeviceMacNotSupportedError` and verifying one fails. `DeviceMac.createDeviceMacKey` is removed, and so is `SessionEstablishment.decryptedData`, which always threw. The `mac` option of a document in `Holder.createDeviceResponseForDeviceRequest` and `DeviceResponse.createWithDeviceRequest` takes `deviceKey` and `ephemeralReaderKey`, as `DeviceSignedBuilder.tag` now does. `DeviceAuth.verify` takes `ephemeralReaderKey`, and `DeviceMac.verify` takes `key` and `peerPublicKey` without `info`.
