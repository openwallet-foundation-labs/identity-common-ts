---
'@owf/cose': minor
'@owf/mdoc': minor
'@owf/token-status-list': minor
---

`Mac0Context` has the same shape as `Sign1Context`. `authenticate` and `verify` get the `CoseKey` passed to the library, and `authenticate` always gets the `algorithm`. The library never reads the key material, so the key can stay in a key management system.

**Breaking:** `Mac0.authenticate` and `Mac0Context` no longer accept a `Uint8Array` key. Pass a `CoseKey`, such as `CoseKey.create({ keyType: KeyType.Oct, k })` for a key held in software, or `CoseKey.create({ keyType: KeyType.Oct, keyId })` for a key in a key management system, and resolve it in the callback. An `algorithm` passed to `Mac0.authenticate` now takes precedence over the `alg` of the key.

**Breaking:** the `CoseKey.privateKey` getter is removed, with `CoseDNotDefinedError`, `CoseKNotDefinedError` and `CoseKeyTypeNotSupportedForPrivateKeyExtractionError`. Read `CoseKey.d` or `CoseKey.k` instead.
