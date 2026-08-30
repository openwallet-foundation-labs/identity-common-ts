import { ES256, parseCertificateChain } from '@owf/crypto'
import { base64urlEncode } from '@owf/identity-common'
import { describe, expect, it } from 'vitest'
import {
  DETACHED_MECHANISM_IDS,
  EtsiUSchema,
  generateSigX5ts,
  generateX5tO,
  generateX5tS256,
  JAdESException,
  JAdESProfile,
  ProtectedHeaderForSigningSchema,
  ProtectedHeaderSchema,
  SigDSchema,
  SignAlgSchema,
  Token,
  UnprotectedHeaderSchema,
  validateProfile,
  verify,
  verifyCompact,
  verifyFlattened,
  verifyGeneral,
  X5tOSchema,
} from '../index'
import type { ProtectedHeaderParams, UnprotectedHeaderParams } from '../types'

const TEST_CERT = `-----BEGIN CERTIFICATE-----
MIIBczCCARmgAwIBAgIUZt2jkmAgIIiw/wpvJU/4yL7ek/YwCgYIKoZIzj0EAwIw
DzENMAsGA1UEAwwEdGVzdDAeFw0yNjAzMTYxODEwMTJaFw0zNjAzMTMxODEwMTJa
MA8xDTALBgNVBAMMBHRlc3QwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASa6ViW
voU/uOZiBHqFWLE/s+3Ts2K6XT9x2S+abUz/xu48DnP8eL89DQRS8TIUewZbW+H6
GBuyFJjG/mSuqJf+o1MwUTAdBgNVHQ4EFgQUFDKBWF8aGWeDTQHphAhWXs9/J1Aw
HwYDVR0jBBgwFoAUFDKBWF8aGWeDTQHphAhWXs9/J1AwDwYDVR0TAQH/BAUwAwEB
/zAKBggqhkjOPQQDAgNIADBFAiEAibvAwfagitnTA7zKxcl8kuUaU+oBLClK8YXg
s2WfHbwCIAQKqu6+GHkzWH8H0zMPKedvxJp34whrGoIarukWZjjp
-----END CERTIFICATE-----`

const TEST_PRIVATE_KEY = {
  kty: 'EC',
  x: 'mulYlr6FP7jmYgR6hVixP7Pt07Niul0_cdkvmm1M_8Y',
  y: '7jwOc_x4vz0NBFLxMhR7Bltb4foYG7IUmMb-ZK6ol_4',
  crv: 'P-256',
  d: 'tLyuDKbdvUfndRfaH3AmHNFG6kHih59RsYdKGZDtYlE',
}
const TEST_PUBLIC_KEY = {
  kty: 'EC',
  x: 'mulYlr6FP7jmYgR6hVixP7Pt07Niul0_cdkvmm1M_8Y',
  y: '7jwOc_x4vz0NBFLxMhR7Bltb4foYG7IUmMb-ZK6ol_4',
  crv: 'P-256',
}
const certs = parseCertificateChain(TEST_CERT)
const claimedAt = 1_780_000_000

const protectedHeader = (): ProtectedHeaderParams => ({ alg: 'ES256', x5c: certs, iat: claimedAt })
const timestamp = { tstTokens: [{ val: 'dGltZXN0YW1w' }] }
const certificateValues = [{ x509Cert: { val: 'Y2VydGlmaWNhdGU=' } }]
const revocationValues = { ocspVals: [{ val: 'b2NzcA==' }] }
const timestampValidationData = { xVals: certificateValues, rVals: revocationValues }

describe('normative component schemas', () => {
  it('accepts IANA algorithm identifiers instead of a closed local list', () => {
    expect(SignAlgSchema.safeParse('EdDSA').success).toBe(true)
    expect(SignAlgSchema.safeParse('').success).toBe(false)
  })

  it('uses Named Information hash identifiers and reserves SHA-256 for x5t#S256', () => {
    expect(X5tOSchema.safeParse({ digAlg: 'sha-384', digVal: 'YWJj' }).success).toBe(true)
    expect(X5tOSchema.safeParse({ digAlg: 'sha-256', digVal: 'YWJj' }).success).toBe(false)
    expect(generateX5tO(certs[0], 'SHA-384').digAlg).toBe('sha-384')
    expect(generateSigX5ts([certs[0], certs[0]], 'SHA-256')[0].digAlg).toBe('sha-256')
    expect(
      ProtectedHeaderSchema.safeParse({
        alg: 'ES256',
        sigX5ts: generateSigX5ts([certs[0], certs[0]], 'SHA-256'),
        iat: claimedAt,
      }).success
    ).toBe(true)
    expect(generateX5tS256(certs[0])).toMatch(/^[A-Za-z0-9_-]+$/)
  })

  it('enforces the v1.2.1 protected-header invariants', () => {
    expect(ProtectedHeaderSchema.safeParse(protectedHeader()).success).toBe(true)
    expect(ProtectedHeaderSchema.safeParse({ ...protectedHeader(), sigT: '2024-01-01T00:00:00Z' }).success).toBe(false)
    expect(ProtectedHeaderSchema.safeParse({ ...protectedHeader(), iat: undefined }).success).toBe(false)
    expect(ProtectedHeaderSchema.safeParse({ ...protectedHeader(), x5t: 'YWJj' }).success).toBe(false)
    expect(ProtectedHeaderForSigningSchema.safeParse(protectedHeader()).success).toBe(true)
    expect(
      ProtectedHeaderForSigningSchema.safeParse({
        alg: 'ES256',
        x5c: certs,
        sigT: '2024-01-01T00:00:00Z',
      }).success
    ).toBe(false)
  })

  it('models sigD arrays and mechanism-specific constraints', () => {
    expect(SigDSchema.safeParse({ mId: DETACHED_MECHANISM_IDS.objectByUri, pars: ['/one'] }).success).toBe(true)
    expect(
      SigDSchema.safeParse({
        mId: DETACHED_MECHANISM_IDS.objectByUriHash,
        pars: ['/one'],
        hashM: 'S256',
        hashV: ['YWJj'],
      }).success
    ).toBe(true)
    expect(SigDSchema.safeParse({ mId: DETACHED_MECHANISM_IDS.httpHeaders, pars: ['Content-Type'] }).success).toBe(
      false
    )
  })

  it('allows only non-empty, homogeneous etsiU arrays in the unprotected header', () => {
    expect(EtsiUSchema.safeParse([{ sigTst: timestamp }]).success).toBe(true)
    expect(EtsiUSchema.safeParse([base64urlEncode(JSON.stringify({ sigTst: timestamp }))]).success).toBe(true)
    expect(EtsiUSchema.safeParse([{ sigTst: timestamp }, 'YWJj']).success).toBe(false)
    expect(UnprotectedHeaderSchema.safeParse({ etsiU: [{ sigTst: timestamp }], kid: 'not-allowed' }).success).toBe(
      false
    )
    expect(EtsiUSchema.safeParse([{ arcTst: timestamp }]).success).toBe(false)
  })
})

describe('Token and verification', () => {
  it('creates and verifies compact, general, and flattened serializations', async () => {
    const token = new Token({ hello: 'world' }).setProtectedHeader(protectedHeader())
    const signer = await ES256.getSigner(TEST_PRIVATE_KEY)
    const verifier = await ES256.getVerifier(TEST_PUBLIC_KEY)
    await token.sign(signer)

    const compact = token.toString()
    const general = token.toJSON()
    const flattened = token.toFlattenedJSON()
    expect((await verifyCompact<{ hello: string }>(compact, verifier)).payload.hello).toBe('world')
    expect((await verifyGeneral(general, verifier)).valid).toBe(true)
    expect((await verifyFlattened(flattened, verifier)).valid).toBe(true)
    expect((await verify(JSON.stringify(flattened), verifier)).valid).toBe(true)
  })

  it('uses iat for new signatures and keeps sigT historical-only', async () => {
    const token = new Token({ value: 1 }).setProtectedHeader({ alg: 'ES256', x5c: certs }).setSigningTime(claimedAt)
    expect(token.getProtectedHeader().iat).toBe(claimedAt)
    expect(token.getProtectedHeader().sigT).toBeUndefined()

    token.setLegacySigningTime('2024-01-01T00:00:00Z')
    const signer = await ES256.getSigner(TEST_PRIVATE_KEY)
    await expect(token.sign(signer)).rejects.toThrow('sigT is prohibited')
  })

  it('invalidates a signature when signed material changes', async () => {
    const token = new Token({ value: 1 }).setProtectedHeader(protectedHeader())
    await token.sign(await ES256.getSigner(TEST_PRIVATE_KEY))
    token.setKid('different-key-reference')
    expect(() => token.toString()).toThrow('Token not signed yet')
  })

  it('adds only RFC-required critical parameters', async () => {
    const sigD = {
      mId: DETACHED_MECHANISM_IDS.objectByUriHash,
      pars: ['https://example.test/object'],
      hashM: 'S256',
      hashV: ['YWJj'],
    }
    const token = new Token({ ignored: true }).setProtectedHeader(protectedHeader()).setDetached(sigD)
    const signer = await ES256.getSigner(TEST_PRIVATE_KEY)
    const verifier = await ES256.getVerifier(TEST_PUBLIC_KEY)
    await token.sign(signer)
    expect(token.getProtectedHeader().crit).toEqual(['sigD'])
    expect(token.toJSON().payload).toBeUndefined()
    expect((await verifyGeneral(token.toJSON(), verifier)).valid).toBe(true)
  })

  it('rejects critical extensions unless the verifier explicitly understands them', async () => {
    const token = new Token({ value: 1 }).setProtectedHeader({
      ...protectedHeader(),
      crit: ['example'],
      example: true,
    })
    const signer = await ES256.getSigner(TEST_PRIVATE_KEY)
    const verifier = await ES256.getVerifier(TEST_PUBLIC_KEY)
    await token.sign(signer)
    await expect(verifyCompact(token.toString(), verifier)).rejects.toThrow('Unsupported critical header parameter')
    expect((await verifyCompact(token.toString(), verifier, { understoodCriticalParameters: ['example'] })).valid).toBe(
      true
    )
  })

  it('verifies a direct detached payload only when the caller supplies it', async () => {
    const payload = 'detached content'
    const token = new Token(payload).setProtectedHeader(protectedHeader()).setDetached({
      mId: DETACHED_MECHANISM_IDS.objectByUri,
      pars: ['https://example.test/object'],
    })
    const signer = await ES256.getSigner(TEST_PRIVATE_KEY)
    const verifier = await ES256.getVerifier(TEST_PUBLIC_KEY)
    await token.sign(signer)
    const serialized = token.toJSON()
    await expect(verifyGeneral(serialized, verifier)).rejects.toThrow('Detached JWS payload is required')
    expect((await verifyGeneral(serialized, verifier, 0, { detachedPayload: payload })).rawPayload).toBe(payload)
  })

  it('enforces JSON serialization when etsiU is present', async () => {
    const token = new Token({ hello: 'world' })
      .setProtectedHeader(protectedHeader())
      .setUnprotectedHeader({ etsiU: [{ sigTst: timestamp }] })
    await token.sign(await ES256.getSigner(TEST_PRIVATE_KEY))
    expect(() => token.toString()).toThrow('Compact JWS cannot carry')
    expect(token.toJSON().signatures[0].header).toEqual({ etsiU: [{ sigTst: timestamp }] })
    expect(() => token.setUnprotectedHeader({ etsiU: [], kid: 'bad' } as never)).toThrow(JAdESException)
  })
})

describe('baseline profile validation', () => {
  const btHeader: UnprotectedHeaderParams = { etsiU: [{ sigTst: timestamp }] }
  const bltItems = [
    { sigTst: timestamp },
    { xVals: certificateValues },
    { rVals: revocationValues },
    { tstVD: timestampValidationData },
  ] as UnprotectedHeaderParams['etsiU']
  const bltHeader: UnprotectedHeaderParams = { etsiU: bltItems }
  const bltaHeader: UnprotectedHeaderParams = {
    etsiU: [
      ...(bltItems as Exclude<UnprotectedHeaderParams['etsiU'], string[]>),
      { arcTst: { canonAlg: 'https://example.test/jcs', ...timestamp } },
    ],
  }

  it('accepts iat, not only the obsolete sigT, at B-B', () => {
    expect(validateProfile(protectedHeader(), JAdESProfile.B_B).valid).toBe(true)
  })

  it('requires exactly one RFC 3161 token in each baseline sigTst', () => {
    expect(validateProfile(protectedHeader(), JAdESProfile.B_T, btHeader).valid).toBe(true)
    const twoTokens: UnprotectedHeaderParams = {
      etsiU: [{ sigTst: { tstTokens: [...timestamp.tstTokens, ...timestamp.tstTokens] } }],
    }
    expect(validateProfile(protectedHeader(), JAdESProfile.B_T, twoTokens).valid).toBe(false)
  })

  it('requires evidence of signature and timestamp validation data at B-LT', () => {
    expect(validateProfile(protectedHeader(), JAdESProfile.B_LT, bltHeader).valid).toBe(true)
    const incomplete: UnprotectedHeaderParams = {
      etsiU: [{ sigTst: timestamp }, { xVals: certificateValues }, { rVals: revocationValues }],
    }
    expect(validateProfile(protectedHeader(), JAdESProfile.B_LT, incomplete).missing).toContain(
      'Validation data for electronic time-stamps is not evidenced'
    )
  })

  it('forbids reference-based validation components at B-LT', () => {
    const withReference = {
      etsiU: [...bltHeader.etsiU, { xRefs: [{ digAlg: 'S256', digVal: 'YWJj' }] }],
    } as UnprotectedHeaderParams
    expect(validateProfile(protectedHeader(), JAdESProfile.B_LT, withReference).valid).toBe(false)
  })

  it('requires an archive timestamp only at B-LTA', () => {
    expect(validateProfile(protectedHeader(), JAdESProfile.B_LTA, bltHeader).valid).toBe(false)
    expect(validateProfile(protectedHeader(), JAdESProfile.B_LTA, bltaHeader).valid).toBe(true)
  })
})
