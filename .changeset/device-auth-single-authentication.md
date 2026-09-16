---
'@owf/mdoc': patch
---

A `DeviceAuth` must contain either a `deviceSignature` or a `deviceMac` (ISO/IEC 18013-5 9.1.3.4), but decoding and `DeviceAuth.create` accepted one with both. `DeviceAuth.verify` then only verified the `deviceSignature` and ignored the `deviceMac`. Decoding and creating a `DeviceAuth` with both or neither now throws a `ValidationError`, and `DeviceAuth.verify` reports a FAILED `Device Auth must contain either a deviceSignature or deviceMac element, but not both` check for one.

When verifying a device MAC threw an error, `DeviceAuth.verify` also reported a FAILED `Device Auth must contain a deviceSignature or deviceMac element` check. It now only reports the FAILED `Device MAC must be valid` check.
