import { createCipheriv } from 'node:crypto'
import { describe, expect, it } from 'vitest'
import { type EncryptBlock, ff1Encrypt } from '../ff1'

const aesEncryptBlock =
  (key: string): EncryptBlock =>
  (block) => {
    const keyBytes = Buffer.from(key, 'hex')
    const cipher = createCipheriv(`aes-${keyBytes.length * 8}-ecb`, keyBytes, null).setAutoPadding(false)
    return new Uint8Array(cipher.update(block))
  }

const toNumber = (numerals: string, radix: number) =>
  [...numerals].reduce((value, numeral) => value * BigInt(radix) + BigInt(Number.parseInt(numeral, radix)), 0n)

const toNumerals = (value: bigint, radix: number, length: number) => value.toString(radix).padStart(length, '0')

const aes128 = '2B7E151628AED2A6ABF7158809CF4F3C'
const aes192 = `${aes128}EF4359D8D580AA4F`
const aes256 = `${aes192}7F036D6F04FC6A94`
const digits = '0123456789'
const alphanumerics = '0123456789abcdefghi'
const digitsTweak = '39383736353433323130'
const alphanumericsTweak = '3737373770717273373737'

describe('ff1Encrypt', () => {
  // https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines/example-values (AES-FF1)
  it.each([
    { sample: 1, key: aes128, radix: 10, plaintext: digits, tweak: '', ciphertext: '2433477484' },
    { sample: 2, key: aes128, radix: 10, plaintext: digits, tweak: digitsTweak, ciphertext: '6124200773' },
    {
      sample: 3,
      key: aes128,
      radix: 36,
      plaintext: alphanumerics,
      tweak: alphanumericsTweak,
      ciphertext: 'a9tv40mll9kdu509eum',
    },
    { sample: 4, key: aes192, radix: 10, plaintext: digits, tweak: '', ciphertext: '2830668132' },
    { sample: 5, key: aes192, radix: 10, plaintext: digits, tweak: digitsTweak, ciphertext: '2496655549' },
    {
      sample: 6,
      key: aes192,
      radix: 36,
      plaintext: alphanumerics,
      tweak: alphanumericsTweak,
      ciphertext: 'xbj3kv35jrawxv32ysr',
    },
    { sample: 7, key: aes256, radix: 10, plaintext: digits, tweak: '', ciphertext: '6657667009' },
    { sample: 8, key: aes256, radix: 10, plaintext: digits, tweak: digitsTweak, ciphertext: '1001623463' },
    {
      sample: 9,
      key: aes256,
      radix: 36,
      plaintext: alphanumerics,
      tweak: alphanumericsTweak,
      ciphertext: 'xs8a0azh2avyalyzuwd',
    },
  ])('matches NIST sample $sample', async ({ key, radix, plaintext, tweak, ciphertext }) => {
    const encrypted = await ff1Encrypt(toNumber(plaintext, radix), plaintext.length, {
      radix,
      tweak: Buffer.from(tweak, 'hex'),
      encryptBlock: aesEncryptBlock(key),
    })

    expect(toNumerals(encrypted, radix, plaintext.length)).toBe(ciphertext)
  })

  it('accepts an async encryptBlock', async () => {
    const encryptBlock = aesEncryptBlock(aes128)
    const encrypted = await ff1Encrypt(toNumber(digits, 10), digits.length, {
      radix: 10,
      encryptBlock: async (block) => encryptBlock(block),
    })

    expect(toNumerals(encrypted, 10, digits.length)).toBe('2433477484')
  })

  it('encrypts P once rather than in every round', async () => {
    const encryptBlock = aesEncryptBlock(aes128)
    let calls = 0
    await ff1Encrypt(0n, 20, {
      radix: 2,
      encryptBlock: (block) => {
        calls++
        return encryptBlock(block)
      },
    })

    expect(calls).toBe(11)
  })

  it('rejects a domain smaller than 1,000,000', async () => {
    const encryptBlock = aesEncryptBlock(aes128)

    await expect(ff1Encrypt(0n, 5, { radix: 10, encryptBlock })).rejects.toThrow('at least 1,000,000')
    await expect(ff1Encrypt(0n, 19, { radix: 2, encryptBlock })).rejects.toThrow('at least 1,000,000')
    await expect(ff1Encrypt(0n, 20, { radix: 2, encryptBlock })).resolves.toBeTypeOf('bigint')
  })

  it('rejects input outside the domain and an invalid radix', async () => {
    const encryptBlock = aesEncryptBlock(aes128)

    await expect(ff1Encrypt(2n ** 20n, 20, { radix: 2, encryptBlock })).rejects.toThrow('outside the domain')
    await expect(ff1Encrypt(-1n, 20, { radix: 2, encryptBlock })).rejects.toThrow('outside the domain')
    await expect(ff1Encrypt(0n, 20, { radix: 1, encryptBlock })).rejects.toThrow('radix')
  })

  it('rejects an encryptBlock that returns the wrong length', async () => {
    await expect(ff1Encrypt(0n, 20, { radix: 2, encryptBlock: () => new Uint8Array(8) })).rejects.toThrow('expected 16')
  })
})
