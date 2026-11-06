import { ES256, parseCertificateChain } from '@owf/crypto'
import { base64urlEncode, bytesToString } from '@owf/identity-common'
import {
  JoseSignatureVerificationError,
  JoseValidationError,
  type JwsSigner,
  type SignJwsCallback,
  type VerifyJwsCallback,
} from '@owf/jose'
import { describe, expect, it } from 'vitest'
import {
  DETACHED_MECHANISM_IDS,
  decodeJades,
  generateSigX5ts,
  generateX5tO,
  generateX5tS256,
  JadesProfile,
  type JadesSerialization,
  JadesValidationError,
  type SignJadesOptions,
  signJades,
  validateProfile,
  verifyJades,
  verifyJadesJwt,
  zEtsiU,
  zProtectedHeader,
  zProtectedHeaderForSigning,
  zSigD,
  zSignAlg,
  zUnprotectedHeader,
  zX5tO,
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
const signWith = await ES256.getSigner(TEST_PRIVATE_KEY)
const verifyWith = await ES256.getVerifier(TEST_PUBLIC_KEY)
const claimedAt = 1_780_000_000

const protectedHeader = (): ProtectedHeaderParams => ({ alg: 'ES256', x5c: certs, iat: claimedAt })
const timestamp = { tstTokens: [{ val: 'dGltZXN0YW1w' }] }
const certificateValues = [{ x509Cert: { val: 'Y2VydGlmaWNhdGU=' } }]
const revocationValues = { ocspVals: [{ val: 'b2NzcA==' }] }
const timestampValidationData = { xVals: certificateValues, rVals: revocationValues }

describe('normative component schemas', () => {
  it('accepts IANA algorithm identifiers instead of a closed local list', () => {
    expect(zSignAlg.safeParse('EdDSA').success).toBe(true)
    expect(zSignAlg.safeParse('').success).toBe(false)
  })

  it('uses Named Information hash identifiers and reserves SHA-256 for x5t#S256', () => {
    expect(zX5tO.safeParse({ digAlg: 'sha-384', digVal: 'YWJj' }).success).toBe(true)
    expect(zX5tO.safeParse({ digAlg: 'sha-256', digVal: 'YWJj' }).success).toBe(false)
    expect(generateX5tO(certs[0], 'SHA-384').digAlg).toBe('sha-384')
    expect(generateSigX5ts([certs[0], certs[0]], 'SHA-256')[0].digAlg).toBe('sha-256')
    expect(
      zProtectedHeader.safeParse({
        alg: 'ES256',
        sigX5ts: generateSigX5ts([certs[0], certs[0]], 'SHA-256'),
        iat: claimedAt,
      }).success
    ).toBe(true)
    expect(generateX5tS256(certs[0])).toMatch(/^[A-Za-z0-9_-]+$/)
  })

  it('enforces the v1.2.1 protected-header invariants', () => {
    expect(zProtectedHeader.safeParse(protectedHeader()).success).toBe(true)
    expect(zProtectedHeader.safeParse({ ...protectedHeader(), sigT: '2024-01-01T00:00:00Z' }).success).toBe(false)
    expect(zProtectedHeader.safeParse({ ...protectedHeader(), iat: undefined }).success).toBe(false)
    expect(zProtectedHeader.safeParse({ ...protectedHeader(), x5t: 'YWJj' }).success).toBe(false)
    expect(zProtectedHeaderForSigning.safeParse(protectedHeader()).success).toBe(true)
    expect(
      zProtectedHeaderForSigning.safeParse({
        alg: 'ES256',
        x5c: certs,
        sigT: '2024-01-01T00:00:00Z',
      }).success
    ).toBe(false)
  })

  it('models sigD arrays and mechanism-specific constraints', () => {
    expect(zSigD.safeParse({ mId: DETACHED_MECHANISM_IDS.objectByUri, pars: ['/one'] }).success).toBe(true)
    expect(
      zSigD.safeParse({
        mId: DETACHED_MECHANISM_IDS.objectByUriHash,
        pars: ['/one'],
        hashM: 'S256',
        hashV: ['YWJj'],
      }).success
    ).toBe(true)
    expect(zSigD.safeParse({ mId: DETACHED_MECHANISM_IDS.httpHeaders, pars: ['Content-Type'] }).success).toBe(false)
  })

  it('allows only non-empty, homogeneous etsiU arrays in the unprotected header', () => {
    expect(zEtsiU.safeParse([{ sigTst: timestamp }]).success).toBe(true)
    expect(zEtsiU.safeParse([base64urlEncode(JSON.stringify({ sigTst: timestamp }))]).success).toBe(true)
    expect(zEtsiU.safeParse([{ sigTst: timestamp }, 'YWJj']).success).toBe(false)
    expect(zUnprotectedHeader.safeParse({ etsiU: [{ sigTst: timestamp }], kid: 'not-allowed' }).success).toBe(false)
    expect(zEtsiU.safeParse([{ arcTst: timestamp }]).success).toBe(false)
  })
})

describe('signing and verification', () => {
  const signer: JwsSigner = { method: 'x5c', alg: 'ES256', x5c: certs }
  const signJwsCallback: SignJwsCallback = async (_, { signingInput }) => ({
    signature: await signWith(signingInput),
    signerJwk: TEST_PUBLIC_KEY,
  })
  const verifyJwsCallback: VerifyJwsCallback = async (_, { signingInput, signature }) =>
    (await verifyWith(signingInput, signature)) ? { verified: true, signerJwk: TEST_PUBLIC_KEY } : { verified: false }

  const sign = <Serialization extends JadesSerialization = 'compact'>(
    options: Partial<SignJadesOptions<Serialization>> = {}
  ) =>
    signJades<Serialization>({
      payload: { hello: 'world' },
      signingTime: claimedAt,
      signer,
      signJwsCallback,
      ...options,
    })

  it.each(['compact', 'flattened', 'general'] as const)(
    'signs and verifies a %s serialization',
    async (serialization) => {
      const { jws, protectedHeader } = await sign({ serialization })

      const verified = await verifyJades({ jws, verifyJwsCallback })

      expect(JSON.parse(bytesToString(verified.payload))).toEqual({ hello: 'world' })
      expect(verified.serialization).toBe(serialization)
      expect(protectedHeader).toMatchObject({ alg: 'ES256', x5c: certs, iat: claimedAt })
    }
  )

  it('uses iat for new signatures and rejects sigT', async () => {
    expect((await sign({ signingTime: new Date(claimedAt * 1000) })).protectedHeader.iat).toBe(claimedAt)
    const error = await sign({ protectedHeader: { sigT: '2024-01-01T00:00:00Z' } }).catch((error) => error)

    expect(error.findIssue('not_allowed')).toMatchObject({ path: ['protected', 'sigT'] })
  })

  it('requires a reference to the signing certificate', async () => {
    const jwkSigner: JwsSigner = { method: 'jwk', alg: 'ES256', publicJwk: TEST_PUBLIC_KEY }

    const error = await sign({ signer: jwkSigner }).catch((error) => error)

    expect(error).toBeInstanceOf(JadesValidationError)
    expect(error.findIssue('missing_certificate_reference')).toMatchObject({ path: ['protected'] })
  })

  it('rejects a signature that does not verify', async () => {
    const { jws } = await sign()

    await expect(verifyJades({ jws, verifyJwsCallback: () => ({ verified: false }) })).rejects.toThrow(
      JoseSignatureVerificationError
    )
  })

  it('marks sigD critical and signs an empty payload for ObjectIdByURIHash', async () => {
    const sigD = {
      mId: DETACHED_MECHANISM_IDS.objectByUriHash,
      pars: ['https://example.test/object'],
      hashM: 'S256',
      hashV: ['YWJj'],
    }

    const { jws, protectedHeader } = await sign({ serialization: 'general', sigD, payload: undefined })

    expect(protectedHeader.crit).toEqual(['sigD'])
    expect(jws.payload).toBeUndefined()
    await expect(verifyJades({ jws, verifyJwsCallback })).resolves.toBeDefined()
    await expect(sign({ sigD })).rejects.toThrow(
      expect.objectContaining({ issues: [expect.objectContaining({ code: 'not_allowed', path: ['payload'] })] })
    )
  })

  it('verifies a direct detached payload only when the caller supplies it', async () => {
    const payload = 'detached content'
    const sigD = { mId: DETACHED_MECHANISM_IDS.objectByUri, pars: ['https://example.test/object'] }

    const { jws } = await sign({ serialization: 'general', sigD, payload })

    await expect(verifyJades({ jws, verifyJwsCallback })).rejects.toThrow('detached payload')
    const verified = await verifyJades({ jws, verifyJwsCallback, detachedPayload: payload })
    expect(bytesToString(verified.payload)).toBe(payload)
  })

  it('rejects critical extensions unless the verifier understands them', async () => {
    const { jws } = await sign({ protectedHeader: { crit: ['example'], example: true } })

    await expect(verifyJades({ jws, verifyJwsCallback })).rejects.toThrow(JoseValidationError)
    await expect(
      verifyJades({ jws, verifyJwsCallback, understoodCriticalParameters: ['example'] })
    ).resolves.toBeDefined()
  })

  it('carries etsiU only in a JSON serialization, and checks the profile it reaches', async () => {
    const unprotectedHeader = { etsiU: [{ sigTst: timestamp }] }

    await expect(sign({ unprotectedHeader })).rejects.toThrow('Compact JWS cannot carry')
    await expect(sign({ serialization: 'general', unprotectedHeader: { etsiU: [] } })).rejects.toThrow(
      JadesValidationError
    )

    const { jws } = await sign({ serialization: 'general', unprotectedHeader })
    expect(jws.signatures[0].header).toEqual(unprotectedHeader)
    await expect(verifyJades({ jws, verifyJwsCallback, profile: JadesProfile.B_T })).resolves.toBeDefined()

    const { jws: compact } = await sign()
    expect(() => decodeJades({ jws: compact, profile: JadesProfile.B_T })).toThrow(
      expect.objectContaining({
        issues: [
          expect.objectContaining({
            code: 'missing_value',
            path: ['header', 'etsiU'],
            context: { expected: 'sigTst' },
          }),
        ],
      })
    )
  })

  it('verifies the claims of a JAdES JWT', async () => {
    const { jws } = await sign({ payload: { iss: 'https://issuer.example', exp: claimedAt + 60 } })

    await expect(
      verifyJadesJwt({ jwt: jws, verifyJwsCallback, now: new Date(claimedAt * 1000) })
    ).resolves.toMatchObject({ payload: { iss: 'https://issuer.example' } })
    await expect(
      verifyJadesJwt({ jwt: jws, verifyJwsCallback, now: new Date((claimedAt + 3600) * 1000) })
    ).rejects.toThrow(JoseValidationError)
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

  it('gives each deviation an issue with a code and a path', () => {
    const header = {
      ...protectedHeader(),
      'x5t#o': { digAlg: 'sha-256', digVal: 'YWJj' },
      sigPl: {},
      sigPId: { id: { id: 'not a uri' }, digAlg: 'md5' },
      sigD: { mId: DETACHED_MECHANISM_IDS.httpHeaders, pars: ['Content-Type'], hashM: 'S256', hashV: ['YWJj'] },
      crit: ['sigD', 'sigD', 'alg'],
    } as ProtectedHeaderParams

    const { valid, issues } = validateProfile(header, JadesProfile.B_B)

    expect(valid).toBe(false)
    expect(issues.map(({ code, path }) => [code, path.join('.')])).toEqual(
      expect.arrayContaining([
        ['invalid_value', 'protected.x5t#o.digAlg'],
        ['too_small', 'protected.sigPl'],
        ['invalid_format', 'protected.sigPId.id.id'],
        ['invalid_value', 'protected.sigPId.digAlg'],
        ['missing_value', 'protected.sigPId.digVal'],
        ['not_allowed', 'protected.sigD.hashM'],
        ['invalid_value', 'protected.sigD.pars'],
        ['invalid_crit', 'protected.crit'],
        ['invalid_value', 'protected.b64'],
      ])
    )
  })

  it('accepts iat, not only the obsolete sigT, at B-B', () => {
    expect(validateProfile(protectedHeader(), JadesProfile.B_B).valid).toBe(true)
  })

  it('requires exactly one RFC 3161 token in each baseline sigTst', () => {
    expect(validateProfile(protectedHeader(), JadesProfile.B_T, btHeader).valid).toBe(true)
    const twoTokens: UnprotectedHeaderParams = {
      etsiU: [{ sigTst: { tstTokens: [...timestamp.tstTokens, ...timestamp.tstTokens] } }],
    }
    expect(validateProfile(protectedHeader(), JadesProfile.B_T, twoTokens).valid).toBe(false)
  })

  it('requires evidence of signature and timestamp validation data at B-LT', () => {
    expect(validateProfile(protectedHeader(), JadesProfile.B_LT, bltHeader).valid).toBe(true)
    const incomplete: UnprotectedHeaderParams = {
      etsiU: [{ sigTst: timestamp }, { xVals: certificateValues }, { rVals: revocationValues }],
    }
    expect(validateProfile(protectedHeader(), JadesProfile.B_LT, incomplete).issues).toEqual([
      expect.objectContaining({
        code: 'missing_validation_data',
        message: 'Validation data for electronic time-stamps is not evidenced',
      }),
    ])
  })

  it('forbids reference-based validation components at B-LT', () => {
    const withReference = {
      etsiU: [...bltHeader.etsiU, { xRefs: [{ digAlg: 'S256', digVal: 'YWJj' }] }],
    } as UnprotectedHeaderParams
    expect(validateProfile(protectedHeader(), JadesProfile.B_LT, withReference).valid).toBe(false)
  })

  it('requires an archive timestamp only at B-LTA', () => {
    expect(validateProfile(protectedHeader(), JadesProfile.B_LTA, bltHeader).valid).toBe(false)
    expect(validateProfile(protectedHeader(), JadesProfile.B_LTA, bltaHeader).valid).toBe(true)
  })
})
