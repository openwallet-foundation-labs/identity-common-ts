---
'@owf/eudi-sca': patch
---

Depend on `@owf/mdoc` from this repository. `createMdocDeviceResponse` now adds the SCA device namespace with `DeviceNamespaces.setDeviceNamespace`, so the namespace is also encoded when the device namespaces of the mdoc were decoded, as `@owf/mdoc` encodes decoded structures with the bytes they were received as until they are modified.
