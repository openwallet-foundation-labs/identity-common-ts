import Crypto from 'node:crypto'
import { hasher as digest, generateSalt } from '@owf/crypto'
import type { Hasher, Signer, Verifier } from '@sd-jwt/core'
import { describe, expect, test, vi } from 'vitest'
import { SdJwtVcInstance } from '..'

const vct = 'http://example.com/example'
const typeMetadata = { vct, name: 'Example' }

const setup = () => {
  const { privateKey, publicKey } = Crypto.generateKeyPairSync('ed25519')
  const signer: Signer = async (data) => Crypto.sign(null, Buffer.from(data), privateKey).toString('base64url')
  const verifier = vi.fn<Verifier>(async (data, sig) =>
    Crypto.verify(null, Buffer.from(data), publicKey, Buffer.from(sig, 'base64url'))
  )
  const hasher = vi.fn<Hasher>(digest)
  const vctFetcher = vi.fn(async () => typeMetadata)
  const sdjwt = new SdJwtVcInstance({
    signer,
    signAlg: 'EdDSA',
    verifier,
    hasher,
    saltGenerator: generateSalt,
    vctFetcher,
  })
  return { sdjwt, verifier, hasher }
}

const payload = { iss: 'https://issuer.example', iat: Math.floor(Date.now() / 1000), vct, firstname: 'John' }

describe('single pass', () => {
  test('verify and safeVerify hash each disclosure once, also when type metadata is loaded', async () => {
    const { sdjwt, hasher } = setup()
    sdjwt.config({ loadTypeMetadataFormat: true })
    const credential = await sdjwt.issue(payload, { _sd: ['firstname'] })

    hasher.mockClear()
    const result = await sdjwt.verify(credential)
    expect(result.typeMetadata?.vctValues).toEqual([vct])
    expect(hasher).toHaveBeenCalledTimes(1)

    hasher.mockClear()
    expect((await sdjwt.safeVerify(credential)).success).toBe(true)
    expect(hasher).toHaveBeenCalledTimes(1)
  })

  test('getVct verifies the signature, unless verifyJwt is false', async () => {
    const { sdjwt, verifier } = setup()
    const credential = await sdjwt.issue(payload, { _sd: ['firstname'] })
    const decoded = await sdjwt.decode(credential)

    expect((await sdjwt.getVct(decoded))?.mergedTypeMetadata).toEqual(typeMetadata)
    expect(verifier).toHaveBeenCalledTimes(1)

    verifier.mockClear()
    expect((await sdjwt.getVct(credential, { verifyJwt: false }))?.mergedTypeMetadata).toEqual(typeMetadata)
    expect((await sdjwt.getVct(decoded, { verifyJwt: false }))?.mergedTypeMetadata).toEqual(typeMetadata)
    expect(verifier).not.toHaveBeenCalled()
  })

  test('issueSdJwt refuses omitTyp like issue', async () => {
    const { sdjwt } = setup()
    sdjwt.config({ omitTyp: true })
    await expect(sdjwt.issueSdJwt(payload)).rejects.toThrowError('omitTyp is not allowed')
    await expect(sdjwt.issue(payload)).rejects.toThrowError('omitTyp is not allowed')
  })
})
