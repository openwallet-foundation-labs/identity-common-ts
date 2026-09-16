---
'@owf/identity-common': minor
'@owf/crypto': patch
'@owf/eudi-jades': patch
'@owf/eudi-sca': patch
'@owf/token-status-list': patch
---

Build all base64, base64url, UTF-8 and JSON encoding on a single implementation in `@owf/identity-common`.

- `base64` and `base64url` share one codec. Decoding input with an impossible length (a single trailing character) now throws instead of returning a corrupt byte.
- `stringToBytes` and `bytesToString` use `TextEncoder` and `TextDecoder`, which must now be available in the environment (see the React Native notes in the README). `bytesToString` and `base64urlDecode` accept `{ fatal: true }` to throw on invalid UTF-8 instead of replacing it.
- `base64urlDecodeJson` and `decodeJwt` build on these layers.

`@owf/crypto`, `@owf/eudi-jades`, `@owf/eudi-sca` and `@owf/token-status-list` use these functions instead of their own `TextEncoder`, `TextDecoder` and `JSON.parse` calls. JSON decoded from base64url (JAdES headers and `etsiU` values, transaction data, and status list token payloads) is now strict about UTF-8.
