import { describe, expect, it } from 'vitest'
import { getAesBlockEncrypter } from '../aes'

const hex = (value: string) => Uint8Array.from(Buffer.from(value, 'hex'))
const plaintext = hex('00112233445566778899aabbccddeeff')

describe('getAesBlockEncrypter', () => {
  // FIPS 197, Appendix C
  it.each([
    { bits: 128, key: '000102030405060708090a0b0c0d0e0f', ciphertext: '69c4e0d86a7b0430d8cdb78070b4c55a' },
    {
      bits: 256,
      key: '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f',
      ciphertext: '8ea2b7ca516745bfeafc49904b496089',
    },
  ])('matches the FIPS 197 AES-$bits example', async ({ key, ciphertext }) => {
    const encryptBlock = await getAesBlockEncrypter(hex(key))

    expect(Buffer.from(await encryptBlock(plaintext)).toString('hex')).toBe(ciphertext)
  })

  it('accepts a non-extractable CryptoKey', async () => {
    const key = await crypto.subtle.importKey('raw', hex('000102030405060708090a0b0c0d0e0f'), 'AES-CBC', false, [
      'encrypt',
    ])
    const encryptBlock = await getAesBlockEncrypter(key)

    expect(Buffer.from(await encryptBlock(plaintext)).toString('hex')).toBe('69c4e0d86a7b0430d8cdb78070b4c55a')
  })

  it('rejects a CryptoKey that is not for AES-CBC encryption', async () => {
    const gcmKey = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 128 }, false, ['encrypt'])
    const decryptOnlyKey = await crypto.subtle.generateKey({ name: 'AES-CBC', length: 128 }, false, ['decrypt'])

    await expect(getAesBlockEncrypter(gcmKey)).rejects.toThrow('got AES-GCM with encrypt')
    await expect(getAesBlockEncrypter(decryptOnlyKey)).rejects.toThrow('got AES-CBC with decrypt')
  })

  it('rejects a block that is not 16 bytes', async () => {
    const encryptBlock = await getAesBlockEncrypter(hex('000102030405060708090a0b0c0d0e0f'))

    await expect(encryptBlock(new Uint8Array(32))).rejects.toThrow('16 bytes')
  })
})
