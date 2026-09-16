---
'@owf/mdoc': patch
---

Fix device MAC authentication (ISO/IEC 18013-5 9.1.3.5), which could neither be created nor verified:

- `DeviceResponse.verify` reported a FAILED `No Device Signature or Device Mac found on Device Auth` check after every device MAC, also a valid one, so `defaultVerificationCallback` threw for every response authenticated with a device MAC.
- `DeviceResponse.createWithDeviceRequest` with `mac` threw a `CoseInvalidAlgorithmError`, and set the algorithm of the device key instead of HMAC 256/256 in the protected header. It now creates a device MAC with HMAC 256/256.
- `DeviceSignedBuilder.tag` threw the same error, and derived the `EMacKey` with SHA-256 of the untagged session transcript instead of the `SessionTranscriptBytes`.
- `DeviceSignedBuilder.tag` throws an `UnsupportedDeviceMacAlgorithmError` for any algorithm other than HMAC 256/256, since `DeviceAuth.verify` rejects any other device MAC.

A session transcript passed as bytes may now be either the `SessionTranscript` or the `SessionTranscriptBytes` (tagged with tag 24) everywhere. Before, the device MAC key was only derived correctly from the tagged bytes. `SessionTranscript.from` normalizes either form.
