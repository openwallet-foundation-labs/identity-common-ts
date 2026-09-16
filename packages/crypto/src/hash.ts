import { sha256 as nobleSha256, sha384 as nobleSha384, sha512 as nobleSha512 } from '@noble/hashes/sha2.js'
import { base64, stringToBytes } from '@owf/identity-common'
import { CryptoException } from './crypto-exception'

export const sha256 = (text: string | ArrayBuffer): Uint8Array => {
  const uint8Array = typeof text === 'string' ? stringToBytes(text) : new Uint8Array(text)
  return nobleSha256(uint8Array)
}

export const sha384 = (text: string | ArrayBuffer): Uint8Array => {
  const uint8Array = typeof text === 'string' ? stringToBytes(text) : new Uint8Array(text)
  return nobleSha384(uint8Array)
}

export const sha512 = (text: string | ArrayBuffer): Uint8Array => {
  const uint8Array = typeof text === 'string' ? stringToBytes(text) : new Uint8Array(text)
  return nobleSha512(uint8Array)
}

type HasherAlgorithm = 'sha256' | 'sha384' | 'sha512' | (string & {})

const toCryptoAlg = (hashAlg: HasherAlgorithm): string =>
  // To cover sha-256, sha256, SHA-256, SHA256
  hashAlg.replace('-', '').toLowerCase()

export const hasher = (data: string | ArrayBuffer, algorithm: HasherAlgorithm = 'sha256'): Uint8Array => {
  const alg = toCryptoAlg(algorithm)

  switch (alg) {
    case 'sha256':
      return sha256(data)
    case 'sha384':
      return sha384(data)
    case 'sha512':
      return sha512(data)
    default:
      throw new CryptoException(`Unsupported algorithm: ${algorithm}`)
  }
}

export type IntegrityAlgorithm = 'sha256' | 'sha384' | 'sha512'

/**
 * Compute a W3C Subresource Integrity (SRI) string for the given data.
 *
 * @see https://www.w3.org/TR/SRI/
 *
 * @example
 * ```typescript
 * import { integrity } from '@owf/crypto'
 *
 * const sri = integrity('hello world')
 * // => "sha256-uU0nuZNNPgilLlLX2n2r+sSE7+N6U4DukIj3rOLvzek="
 * ```
 */
export const integrity = (data: string | ArrayBuffer, algorithm: IntegrityAlgorithm = 'sha256'): string => {
  const hash = hasher(data, algorithm)
  return `${algorithm}-${base64.encode(hash)}`
}
