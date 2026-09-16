---
'@owf/mdoc': minor
---

`IssuerSigned` now decodes and encodes without `nameSpaces`, so `IssuerSigned.issuerNamespaces` can be `undefined`. 18013-5 requires `IssuerNameSpaces` to have at least one namespace, so when `DeviceResponse.createWithDeviceRequest` discloses no issuer-signed element, `issuerSigned.nameSpaces` is left out instead of encoded as an empty map.
