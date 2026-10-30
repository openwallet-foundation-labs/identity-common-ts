---
"@owf/token-status-list": patch
---

Add `FeistelStatusListIndexAllocator` for status lists of 1,000,000 indices or more. It assigns each index by encrypting the position with FF1 (NIST SP 800-38G) under an AES key that stays in a caller-provided `encryptBlock` callback. With a unique `tweak` per list, such as its URI, one key can serve several lists. Creating or resuming one takes under 1 µs, against about 250 ms for `StatusListIndexAllocator` with 1,000,000 indices, and `next()` is asynchronous.
