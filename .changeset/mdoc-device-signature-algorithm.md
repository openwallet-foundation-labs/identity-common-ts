---
'@owf/mdoc': minor
---

The `signature` of a document passed to `DeviceResponse.createWithDeviceRequest` and `Holder.createDeviceResponseForDeviceRequest` takes the `algorithm` of the device signature, the same as `Issuer.sign`. The documents of `IsoMdocDcApi.createResponse` take it as `algorithm` next to `deviceKey`, and the `readerAuth` of `IsoMdocDcApi.createRequest` takes `algorithm` for the reader auth signature. A signing key with another `alg` throws a `SignatureAlgorithmDoesNotMatchSigningKeyAlgorithmError`. Before, the algorithm came from the `alg` of the signing key, so a key without one could not sign.

`DeviceSignedBuilder.sign` signs with its `algorithm`. Before, it put `algorithm` in the protected header but signed with the `alg` of the signing key, and threw for a key without one.

**Breaking:** pass `algorithm` with every device signature and reader auth, for example `signature: { signingKey, algorithm: SignatureAlgorithm.ES256 }`.
