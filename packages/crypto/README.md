# @owf/crypto

Cryptographic utilities using the Web Crypto API and `@noble/hashes`. Platform-agnostic — works in Node.js (>=20), browsers, and React Native.

## Features

- **Salt generation** via `crypto.getRandomValues`
- **Hashing** via Web Crypto `subtle.digest` and `@noble/hashes` (SHA-256/384/512)
- **ECDSA key generation** (ES256, ES384, ES512)
- **Signing and verification** via Web Crypto `subtle`
- **AES block encryption** via Web Crypto `subtle`, for FF1 in `@owf/token-status-list`

## Installation

```bash
npm install @owf/crypto
```

## Usage

```typescript
import { generateSalt, digest, getHasher, ES256, sha256, hasher, getAesBlockEncrypter } from '@owf/crypto'

// Generate a random hex salt
const salt = generateSalt(16)

// Hash with Web Crypto (async)
const hash = await digest('hello', 'sha-256')

// Hash with @noble/hashes (sync)
const hash2 = sha256('hello')

// Flexible hasher supporting multiple algorithms
const hash3 = hasher('hello', 'sha-512')

// ES256 key generation, signing, and verification
const { publicKey, privateKey } = await ES256.generateKeyPair()
const signer = await ES256.getSigner(privateKey)
const verifier = await ES256.getVerifier(publicKey)
const signature = await signer('data to sign')
const isValid = await verifier('data to sign', signature)

// Encrypt single 16-byte blocks with AES (AES-ECB without padding)
const encryptBlock = await getAesBlockEncrypter(aesKey) // raw key bytes, or an AES-CBC CryptoKey with the encrypt usage
const ciphertext = await encryptBlock(block)
```
