---
'@owf/cose': minor
'@owf/mdoc': minor
---

`Mac0` now puts an empty `external_aad` in the MAC_structure when none is passed, as RFC 9052 6.3 requires. It was left out, so tags didn't match other COSE implementations. The device MAC of `@owf/mdoc` now matches the example in ISO/IEC 18013-5 D.5.3.

Tags created with an earlier version without `externalAad` still verify. When a tag doesn't match and no `externalAad` is passed, `Mac0.verifyAuthenticationCode` and `DeviceMac.verify` check it once more against the MAC_structure without `external_aad`.

**Breaking:** earlier versions don't verify a tag created with this version without `externalAad`.
