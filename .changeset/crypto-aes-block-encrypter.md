---
"@owf/crypto": patch
---

Add `getAesBlockEncrypter`, which encrypts single 16-byte blocks with AES using Web Crypto. Pass it as `encryptBlock` to `FeistelStatusListIndexAllocator` from `@owf/token-status-list`.
