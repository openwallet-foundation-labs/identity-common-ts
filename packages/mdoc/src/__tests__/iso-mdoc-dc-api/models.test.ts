import { cborDecode, cborEncode } from '@owf/cose'
import { base64url, hex } from '@owf/identity-common'
import { describe, expect, test } from 'vitest'
import { CoseKey, EncryptedResponse, EncryptedResponseData, EncryptionInfo, EncryptionParameters } from '../..'
import { RECIPIENT_JWK_PUBLIC } from './fixtures'

const nonce = hex.decode('000102030405060708090a0b0c0d0e0f')

describe('Annex C models', () => {
  test('EncryptionInfo round-trips through CBOR', () => {
    const encryptionInfo = EncryptionInfo.create({
      encryptionParameters: EncryptionParameters.create({
        nonce,
        recipientPublicKey: CoseKey.fromJwk(RECIPIENT_JWK_PUBLIC),
      }),
    })

    const decoded = EncryptionInfo.decode(encryptionInfo.encode())

    expect(decoded.nonce).toStrictEqual(nonce)
    expect(decoded.recipientPublicKey.publicKey).toStrictEqual(CoseKey.fromJwk(RECIPIENT_JWK_PUBLIC).publicKey)
  })

  test('EncryptionInfo is a ["dcapi", EncryptionParameters] array', () => {
    const encryptionInfo = EncryptionInfo.create({
      encryptionParameters: EncryptionParameters.create({
        nonce,
        recipientPublicKey: CoseKey.fromJwk(RECIPIENT_JWK_PUBLIC),
      }),
    })

    const raw = cborDecode<[string, Map<string, unknown>]>(encryptionInfo.encode())

    expect(raw[0]).toBe('dcapi')
    expect(raw[1].get('nonce')).toStrictEqual(nonce)
    expect(raw[1].has('recipientPublicKey')).toBe(true)
  })

  test('EncryptionInfo base64url helpers use no padding', () => {
    const encryptionInfo = EncryptionInfo.create({
      encryptionParameters: EncryptionParameters.create({
        nonce,
        recipientPublicKey: CoseKey.fromJwk(RECIPIENT_JWK_PUBLIC),
      }),
    })

    const encoded = encryptionInfo.toBase64Url()

    expect(encoded).not.toContain('=')
    expect(EncryptionInfo.fromBase64Url(encoded).nonce).toStrictEqual(nonce)
  })

  test('EncryptionParameters tolerates unknown keys (6.4.1)', () => {
    const coseKey = CoseKey.fromJwk(RECIPIENT_JWK_PUBLIC)
    const bytes = cborEncode([
      'dcapi',
      new Map<string, unknown>([
        ['nonce', nonce],
        ['recipientPublicKey', coseKey.encodedStructure],
        ['somethingFromALaterEdition', 'ignore me'],
      ]),
    ])

    expect(EncryptionInfo.decode(bytes).nonce).toStrictEqual(nonce)
  })

  test('EncryptedResponse round-trips through CBOR', () => {
    const enc = new Uint8Array(65).fill(4)
    const ciphertext = hex.decode('deadbeef')

    const encryptedResponse = EncryptedResponse.create({
      encryptedResponseData: EncryptedResponseData.create({ enc, ciphertext }),
    })

    const raw = cborDecode<[string, Map<string, unknown>]>(encryptedResponse.encode())
    expect(raw[0]).toBe('dcapi')

    const decoded = EncryptedResponse.fromBase64Url(base64url.encode(encryptedResponse.encode()))
    expect(decoded.enc).toStrictEqual(enc)
    expect(decoded.ciphertext).toStrictEqual(ciphertext)
  })

  test('EncryptionInfo rejects a payload that is not tagged "dcapi"', () => {
    const coseKey = CoseKey.fromJwk(RECIPIENT_JWK_PUBLIC)
    const bytes = cborEncode([
      'not-dcapi',
      new Map<string, unknown>([
        ['nonce', nonce],
        ['recipientPublicKey', coseKey.encodedStructure],
      ]),
    ])

    expect(() => EncryptionInfo.decode(bytes)).toThrow()
  })
})
