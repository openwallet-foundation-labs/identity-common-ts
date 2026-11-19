import Crypto from 'node:crypto'
import { hasher as digest, generateSalt } from '@owf/crypto'
import { describe, expect, test, vi } from 'vitest'
import { SdJwtInstance, type SdJwtPayload } from '../index'
import { Jwt } from '../jwt'
import type { DisclosureFrame, Hasher, Signer, Verifier } from '../types'

const setup = () => {
  const { privateKey, publicKey } = Crypto.generateKeyPairSync('ed25519')
  const signer: Signer = async (data) => Crypto.sign(null, Buffer.from(data), privateKey).toString('base64url')
  const verifier: Verifier = async (data, sig) =>
    Crypto.verify(null, Buffer.from(data), publicKey, Buffer.from(sig, 'base64url'))
  const hasher = vi.fn<Hasher>(digest)
  const sdjwt = new SdJwtInstance<SdJwtPayload>({
    signer,
    signAlg: 'EdDSA',
    verifier,
    hasher,
    saltGenerator: generateSalt,
    kbSigner: signer,
    kbVerifier: verifier,
    kbSignAlg: 'EdDSA',
  })
  return { sdjwt, hasher }
}

const claims = { firstname: 'John', lastname: 'Doe', address: { city: 'Utrecht' } }
const frame: DisclosureFrame<typeof claims> = { _sd: ['firstname', 'lastname'], address: { _sd: ['city'] } }
const kb = { payload: { aud: 'verifier', iat: Math.floor(Date.now() / 1000), nonce: 'nonce' } }

describe('single pass', () => {
  test('verify hashes each disclosure once', async () => {
    const { sdjwt, hasher } = setup()
    const presentation = await sdjwt.present(await sdjwt.issue(claims, frame), undefined, { kb })
    const disclosures = presentation.split('~').slice(1, -1)
    expect(disclosures).toHaveLength(3)

    hasher.mockClear()
    await sdjwt.verify(presentation, {
      keyBindingNonce: 'nonce',
      requiredClaimKeys: ['firstname', 'address.city'],
    })

    for (const disclosure of disclosures) {
      expect(hasher.mock.calls.filter(([data]) => data === disclosure)).toHaveLength(1)
    }
    // And the sd_hash of the presentation
    expect(hasher).toHaveBeenCalledTimes(disclosures.length + 1)
  })

  test('verify, validate, present and getClaims accept a decoded SD-JWT without hashing its disclosures again', async () => {
    const { sdjwt, hasher } = setup()
    const credential = await sdjwt.issue(claims, frame)
    const decoded = await sdjwt.decode(credential)
    const keys = await sdjwt.keys(credential)
    const presentation = await sdjwt.present(credential, { firstname: true })

    hasher.mockClear()
    expect(await sdjwt.getClaims(decoded)).toEqual(claims)
    expect(await sdjwt.keys(decoded)).toEqual(keys)
    expect((await sdjwt.validate(decoded)).payload).toEqual(claims)
    expect((await sdjwt.verify(decoded)).payload).toEqual(claims)
    expect((await sdjwt.safeVerify(decoded)).success).toBe(true)
    expect(await sdjwt.present(decoded, { firstname: true })).toEqual(presentation)
    expect(hasher).not.toHaveBeenCalled()

    // Presenting does not add the Key Binding JWT to the decoded SD-JWT
    const keyBound = await sdjwt.present(decoded, { firstname: true }, { kb })
    expect(decoded.kbJwt).toBeUndefined()
    expect((await sdjwt.verify(keyBound, { keyBindingNonce: 'nonce' })).payload).toEqual({
      firstname: 'John',
      address: {},
    })
  })

  test('issueSdJwt returns the decoded SD-JWT of what issue returns', async () => {
    const { sdjwt, hasher } = setup()
    const issued = await sdjwt.issueSdJwt(claims, frame)
    const compact = issued.encodeSdJwt()

    hasher.mockClear()
    expect(await sdjwt.getClaims(issued)).toEqual(claims)
    expect(hasher).not.toHaveBeenCalled()
    expect((await sdjwt.verify(compact)).payload).toEqual(claims)
  })

  test('Jwt.sign returns the token with the new signature', async () => {
    const jwt = new Jwt({ header: { alg: 'EdDSA' }, payload: { a: 1 } })
    const first = await jwt.sign(async () => 'first')
    expect(first.endsWith('.first')).toBe(true)
    expect(await Jwt.fromEncode(first).sign(async () => 'second')).toBe(first.replace(/first$/, 'second'))
  })
})
