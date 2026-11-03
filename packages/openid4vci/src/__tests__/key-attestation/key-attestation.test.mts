import { type Jwk, signJwt } from '@owf/jose'
import * as jose from 'jose'
import { beforeAll, describe, expect, test } from 'vitest'
import { callbacks, getSignJwsCallback } from '../../../../oauth2/src/__tests__/util.mjs'
import {
  createKeyAttestationJwt,
  parseKeyAttestationJwt,
  verifyKeyAttestationJwt,
  verifyKeyAttestationRequirements,
} from '../../key-attestation/key-attestation'
import { zKeyAttestationJwtHeader, zKeyAttestationJwtPayloadForUse } from '../../key-attestation/z-key-attestation'

async function generateEs256Key() {
  const { publicKey, privateKey } = await jose.generateKeyPair('ES256', { extractable: true })
  return {
    privateJwk: (await jose.exportJWK(privateKey)) as Jwk,
    publicJwk: (await jose.exportJWK(publicKey)) as Jwk,
  }
}

describe('Key Attestation', () => {
  let attester: Awaited<ReturnType<typeof generateEs256Key>>
  let attested: Awaited<ReturnType<typeof generateEs256Key>>
  let signJws: ReturnType<typeof getSignJwsCallback>

  beforeAll(async () => {
    attester = await generateEs256Key()
    attested = await generateEs256Key()
    signJws = getSignJwsCallback([attester.privateJwk])
  })

  test('creates a key attestation with the spec `key-attestation+jwt` typ', async () => {
    const keyAttestationJwt = await createKeyAttestationJwt({
      callbacks: { signJws },
      attestedKeys: [attested.publicJwk],
      expiresAt: new Date(Date.now() + 500 * 1000),
      use: 'proof_type.jwt',
      signer: { method: 'jwk', alg: 'ES256', publicJwk: attester.publicJwk },
    })

    const { header } = parseKeyAttestationJwt({ keyAttestationJwt })
    expect(header.typ).toBe('key-attestation+jwt')

    await expect(
      verifyKeyAttestationJwt({
        callbacks: { verifyJws: callbacks.verifyJws },
        keyAttestationJwt,
        use: 'proof_type.jwt',
      })
    ).resolves.toBeDefined()
  })

  test('verifies a legacy `keyattestation+jwt` key attestation', async () => {
    const now = Math.floor(Date.now() / 1000)
    const { jwt: legacyKeyAttestationJwt } = await signJwt({
      signer: { method: 'jwk', alg: 'ES256', publicJwk: attester.publicJwk },
      signJwsCallback: signJws,
      header: { typ: 'keyattestation+jwt', alg: 'ES256', jwk: attester.publicJwk },
      payload: { iat: now, exp: now + 500, attested_keys: [attested.publicJwk] },
    })

    await expect(
      verifyKeyAttestationJwt({
        callbacks: { verifyJws: callbacks.verifyJws },
        keyAttestationJwt: legacyKeyAttestationJwt,
        use: 'proof_type.jwt',
      })
    ).resolves.toBeDefined()
  })

  describe('typ', () => {
    // A key attestation as `createKeyAttestationJwt` creates it, but with the given typ
    const signKeyAttestationJwt = async (typ: string) => {
      const now = Math.floor(Date.now() / 1000)
      const { jwt } = await signJwt({
        signer: { method: 'jwk', alg: 'ES256', publicJwk: attester.publicJwk },
        signJwsCallback: signJws,
        header: { typ, alg: 'ES256', jwk: attester.publicJwk },
        payload: { iat: now, exp: now + 500, attested_keys: [attested.publicJwk] },
      })

      return jwt
    }

    test.each([
      'application/key-attestation+jwt',
      'Key-Attestation+JWT',
      // The legacy typ, in the same forms
      'application/keyattestation+jwt',
      'KeyAttestation+JWT',
    ])('verifies a key attestation whose typ is %s', async (typ) => {
      const { header } = await verifyKeyAttestationJwt({
        callbacks: { verifyJws: callbacks.verifyJws },
        keyAttestationJwt: await signKeyAttestationJwt(typ),
        use: 'proof_type.jwt',
      })

      expect(header.typ).toEqual(typ)
    })

    test('rejects a jwt whose typ is not key-attestation+jwt or keyattestation+jwt', async () => {
      await expect(
        verifyKeyAttestationJwt({
          callbacks: { verifyJws: callbacks.verifyJws },
          keyAttestationJwt: await signKeyAttestationJwt('openid4vci-proof+jwt'),
          use: 'proof_type.jwt',
        })
      ).rejects.toThrow(`typ: typ must be key-attestation+jwt or keyattestation+jwt (invalid_typ)`)
    })
  })

  describe('allowedSkewInSeconds', () => {
    const now = new Date('2026-01-01T00:00:00Z')

    const verify = async (allowedSkewInSeconds?: number) =>
      verifyKeyAttestationJwt({
        callbacks: { verifyJws: callbacks.verifyJws },
        keyAttestationJwt: await createKeyAttestationJwt({
          callbacks: { signJws },
          attestedKeys: [attested.publicJwk],
          issuedAt: new Date(now.getTime() - 100 * 1000),
          expiresAt: new Date(now.getTime() - 10 * 1000),
          use: 'proof_type.jwt',
          signer: { method: 'jwk', alg: 'ES256', publicJwk: attester.publicJwk },
        }),
        use: 'proof_type.jwt',
        now,
        allowedSkewInSeconds,
      })

    test('accepts a key attestation that expired 10 seconds ago with the default skew', async () => {
      await expect(verify()).resolves.toBeDefined()
    })

    test('rejects a key attestation that expired 10 seconds ago with an allowed skew of 0', async () => {
      await expect(verify(0)).rejects.toThrow(/exp: .* \(expired\)/)
    })
  })

  test('accepts a header with both `trust_chain` and `kid`, rejects `trust_chain` without `kid`', () => {
    const base = { typ: 'key-attestation+jwt', alg: 'ES256' } as const

    expect(zKeyAttestationJwtHeader.safeParse({ ...base, trust_chain: ['chain'], kid: '1' }).success).toBe(true)
    expect(zKeyAttestationJwtHeader.safeParse({ ...base, trust_chain: ['chain'] }).success).toBe(false)
  })

  test('rejects an empty `attested_keys` array', () => {
    const now = Math.floor(Date.now() / 1000)
    const result = zKeyAttestationJwtPayloadForUse('proof_type.jwt').safeParse({
      iat: now,
      exp: now + 500,
      attested_keys: [],
    })
    expect(result.success).toBe(false)
  })

  test('allows an attestation-proof key attestation without `nonce`', () => {
    const now = Math.floor(Date.now() / 1000)
    const result = zKeyAttestationJwtPayloadForUse('proof_type.attestation').safeParse({
      iat: now,
      attested_keys: [attested.publicJwk],
    })
    expect(result.success).toBe(true)
  })
})

describe('verifyKeyAttestationRequirements', () => {
  test('does not require a key attestation if the issuer has no requirements', () => {
    expect(() => verifyKeyAttestationRequirements({})).not.toThrow()
    expect(() =>
      verifyKeyAttestationRequirements({ keyAttestation: { key_storage: ['iso_18045_basic'] } })
    ).not.toThrow()
  })

  test('requires a key attestation if the issuer defines key_attestations_required', () => {
    expect(() => verifyKeyAttestationRequirements({ keyAttestationsRequired: {} })).toThrow(
      'A key attestation is required by the credential issuer, but no key attestation was provided'
    )

    // An empty object means a key attestation is needed, without additional constraints
    expect(() => verifyKeyAttestationRequirements({ keyAttestation: {}, keyAttestationsRequired: {} })).not.toThrow()
  })

  test('accepts a key attestation that contains one of the accepted values', () => {
    expect(() =>
      verifyKeyAttestationRequirements({
        keyAttestation: {
          key_storage: ['iso_18045_moderate', 'iso_18045_high'],
          user_authentication: ['iso_18045_high'],
        },
        keyAttestationsRequired: {
          key_storage: ['iso_18045_high'],
          user_authentication: ['iso_18045_high', 'iso_18045_moderate'],
        },
      })
    ).not.toThrow()
  })

  test('rejects a key attestation whose key_storage does not match', () => {
    expect(() =>
      verifyKeyAttestationRequirements({
        keyAttestation: { key_storage: ['iso_18045_basic'], user_authentication: ['iso_18045_high'] },
        keyAttestationsRequired: { key_storage: ['iso_18045_high', 'iso_18045_moderate'] },
      })
    ).toThrow(
      "Key attestation 'key_storage' values 'iso_18045_basic' do not match any of the values accepted by the credential issuer: 'iso_18045_high', 'iso_18045_moderate'"
    )
  })

  test('rejects a key attestation that does not define a required claim', () => {
    expect(() =>
      verifyKeyAttestationRequirements({
        keyAttestation: { key_storage: ['iso_18045_high'] },
        keyAttestationsRequired: { key_storage: ['iso_18045_high'], user_authentication: ['iso_18045_high'] },
      })
    ).toThrow(
      "Key attestation 'user_authentication' is not defined and does not match any of the values accepted by the credential issuer: 'iso_18045_high'"
    )
  })
})
