import { CryptoException } from './crypto-exception'

const BLOCK_SIZE = 16

/**
 * Returns a function that encrypts one 16-byte block with AES under `key` (AES-ECB without
 * padding), as FF1 needs. Web Crypto has no ECB mode, so it uses AES-CBC with a zero IV, which
 * encrypts a single block the same way.
 *
 * @param key Raw AES key bytes (16, 24 or 32), or a `CryptoKey` for `AES-CBC` with the `encrypt` usage.
 */
export async function getAesBlockEncrypter(key: Uint8Array | CryptoKey) {
  if (!(key instanceof Uint8Array) && (key.algorithm.name !== 'AES-CBC' || !key.usages.includes('encrypt'))) {
    throw new CryptoException(
      `CryptoKey must be an AES-CBC key with the encrypt usage, got ${key.algorithm.name} with ${key.usages.join(', ') || 'no usages'}`
    )
  }

  const cryptoKey =
    key instanceof Uint8Array
      ? await globalThis.crypto.subtle.importKey('raw', new Uint8Array(key), 'AES-CBC', false, ['encrypt'])
      : key
  const iv = new Uint8Array(BLOCK_SIZE)

  return async (block: Uint8Array<ArrayBuffer>): Promise<Uint8Array> => {
    if (block.length !== BLOCK_SIZE) {
      throw new CryptoException(`AES block must be ${BLOCK_SIZE} bytes, got ${block.length}`)
    }
    const encrypted = await globalThis.crypto.subtle.encrypt({ name: 'AES-CBC', iv }, cryptoKey, block)
    return new Uint8Array(encrypted, 0, BLOCK_SIZE)
  }
}
