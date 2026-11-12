---
'@owf/token-status-list': minor
---

`verifyStatus` verifies the signature of the Status List Token before it reads its claims and the status, with a `verifySignature` callback (Token Status List Section 8.3), and rejects a token with a `crit` header (RFC 7515 Section 4.1.11). Before, it checked the header, the claims and the status of a token whose signature it never verified, so whoever could serve the status list, such as a cache or a network attacker on an http uri, could mark a revoked credential as valid.

`StatusList.decompressStatusListFromBytes` stops inflating a list larger than `maxDecompressedBytes`, 16 MiB by default. A few KiB of compressed data could inflate to a list that exhausts the memory and CPU of whoever reads it, for example through `getListFromStatusListJwt` or a `StatusListCwt`.

**Breaking:** `verifyStatus` is async and requires `verifySignature`, which gets the header, the JWS signing input and the signature, and returns whether the signature verifies with the key of a trusted status list issuer.
