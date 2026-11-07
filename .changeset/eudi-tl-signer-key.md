---
'@owf/eudi-tl': minor
---

`verifyTrustedListSignature`, `verifyEuLotlSignature`, `loadTrustedList` and `loadEuLotl` verify the signature of a trusted list with the key of the pinned signer certificate (ETSI TS 119 612 clause 5.7.1). Before, a list signed with any key passed as long as a pinned certificate was in its unsigned `KeyInfo`, so a forged EU List of Trusted Lists made any national list trusted. A list with more than one `ds:Signature` is rejected, and `parseTrustedList` reads the scheme information and the trust service providers only from their place in the list, so providers added to unsigned parts of the document are no longer returned. An empty `trustAnchors` fails closed instead of skipping the pin.

**Breaking:** `loadTrustedList` requires `trustAnchors`, because without them it only checked the integrity of the list. Pass the certificates of the scheme operator, or call `verifyTrustedListSignature` and `parseTrustedList` to check the integrity only.
