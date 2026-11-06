import {
  cborDecode,
  cborEncode,
  RegisteredCwtClaimKey,
  RegisteredCwtHeaderClaimKey,
  Sign1,
  SignatureAlgorithm,
} from '@owf/cose'
import { stringToBytes } from '@owf/identity-common'
import { describe, expect, it } from 'vitest'
import {
  decodeRegistrationCertificateCwt,
  RegistrationCertificateCwt,
  RegistrationCertificateCwtPayload,
  RegistrationCertificateValidationError,
  signRegistrationCertificateCwt,
} from '../index'
import { payload, SUB, sign1Context, signingKey, TEST_CERT } from './context.mjs'

const sign = () =>
  signRegistrationCertificateCwt({
    payload,
    accessCertificateSub: SUB,
    certificates: [TEST_CERT],
    signingKey,
    signCoseCallback: sign1Context.sign,
  })

/** A COSE_Sign1 with the given protected header and claims, as another implementation may produce it */
const cwtWith = async ({
  protectedHeaders = new Map<number, unknown>([
    [RegisteredCwtHeaderClaimKey.Algorithm, SignatureAlgorithm.ES256],
    [RegisteredCwtHeaderClaimKey.Typ, 'rc-wrp+cwt'],
    [RegisteredCwtHeaderClaimKey.X5Chain, new Uint8Array([1, 2, 3])],
  ]),
  unprotectedHeaders,
  claims = new Map<unknown, unknown>(Object.entries(JSON.parse(JSON.stringify(payload)))),
}: {
  protectedHeaders?: Map<number, unknown>
  unprotectedHeaders?: Map<number, unknown>
  claims?: Map<unknown, unknown>
}) => {
  const sign1 = Sign1.create({ protectedHeaders, unprotectedHeaders, payload: cborEncode(claims) })
  await sign1.sign({ signingKey }, sign1Context)
  return sign1
}

describe('signRegistrationCertificateCwt', () => {
  it('signs the payload as a CBOR map with the registered CWT claims in a COSE_Sign1 that verifies', async () => {
    const signed = await sign()

    const sign1 = cborDecode(signed.cwt)
    expect(sign1).toBeInstanceOf(Sign1)
    expect(await (sign1 as Sign1).verifySignature({ key: signingKey }, sign1Context)).toBe(true)

    const claims = cborDecode<Map<unknown, unknown>>((sign1 as Sign1).payload as Uint8Array)
    expect(claims.get(RegisteredCwtClaimKey.Subject)).toBe(SUB)
    expect(claims.get(RegisteredCwtClaimKey.IssuedAt)).toBe(1_700_000_000)
    expect(claims.get(RegisteredCwtClaimKey.ExpirationTime)).toBe(1_710_000_000)
    expect(claims.get(RegisteredCwtClaimKey.CwtId)).toStrictEqual(stringToBytes('wrprc-1'))
    // Token Status List section 6.3
    expect(claims.get(65535)).toStrictEqual(
      new Map([
        [
          'status_list',
          new Map<string, unknown>([
            ['idx', 3],
            ['uri', 'https://registry.test/statuslists/1'],
          ]),
        ],
      ])
    )
    expect(claims.get('supervisory_authority')).toStrictEqual(new Map([['email', 'dpa@example.nl']]))
    expect([...claims.keys()].filter((key) => ['sub', 'iat', 'exp', 'jti', 'status'].includes(key as string))).toEqual(
      []
    )

    const headers = (sign1 as Sign1).protectedHeaders.headers
    expect(headers.get(RegisteredCwtHeaderClaimKey.Typ)).toBe('rc-wrp+cwt')
    expect(headers.get(RegisteredCwtHeaderClaimKey.Algorithm)).toBe(SignatureAlgorithm.ES256)
    expect(headers.get(RegisteredCwtHeaderClaimKey.X5Chain)).toBeInstanceOf(Uint8Array)
  })

  it('decodes to the payload it signed', async () => {
    const signed = await sign()

    const decoded = decodeRegistrationCertificateCwt(signed.cwt, SUB)

    expect(decoded.payload).toStrictEqual(payload)
    expect(decoded.header).toStrictEqual(signed.header)
    expect(decoded.header.x5chain).toHaveLength(1)
  })

  it('signs a claims set that was extended before signing', async () => {
    const claimsSet = RegistrationCertificateCwtPayload.fromRegistrationCertificate(payload)
    claimsSet.claims.set(RegisteredCwtClaimKey.Issuer, 'https://registrar.example')

    const signed = await signRegistrationCertificateCwt({
      payload: claimsSet,
      accessCertificateSub: SUB,
      certificates: [TEST_CERT],
      signingKey,
      signCoseCallback: sign1Context.sign,
    })

    expect(RegistrationCertificateCwt.fromToken(signed.cwt).payload.issuer).toBe('https://registrar.example')
    expect(signed.payload).toStrictEqual(payload)
  })

  it('rejects a payload for another access certificate', async () => {
    await expect(
      signRegistrationCertificateCwt({
        payload,
        accessCertificateSub: 'LEINL-OTHER',
        certificates: [TEST_CERT],
        signingKey,
        signCoseCallback: sign1Context.sign,
      })
    ).rejects.toThrow(RegistrationCertificateValidationError)
  })
})

describe('decodeRegistrationCertificateCwt', () => {
  it('reads an untagged COSE_Sign1', async () => {
    const sign1 = cborDecode<Sign1>((await sign()).cwt)

    expect(decodeRegistrationCertificateCwt(cborEncode(sign1.encodedStructure), SUB).payload).toStrictEqual(payload)
  })

  it('reads the registered claims under their JSON name too', async () => {
    const decoded = decodeRegistrationCertificateCwt((await cwtWith({})).encode(), SUB)

    expect(decoded.payload).toStrictEqual(payload)
  })

  it('rejects a cti that is not UTF-8', async () => {
    const { jti, ...rest } = JSON.parse(JSON.stringify(payload))
    const claims = new Map<unknown, unknown>([
      ...Object.entries(rest),
      [RegisteredCwtClaimKey.CwtId, new Uint8Array([0xff])],
    ])

    const cwt = (await cwtWith({ claims })).encode()

    expect(() => decodeRegistrationCertificateCwt(cwt, SUB)).toThrow(RegistrationCertificateValidationError)
  })

  it('rejects a claim under both its name and its CWT key', async () => {
    const claims = new Map<unknown, unknown>([
      ...Object.entries(JSON.parse(JSON.stringify(payload))),
      [RegisteredCwtClaimKey.IssuedAt, 1_600_000_000],
    ])

    const cwt = (await cwtWith({ claims })).encode()

    expect(() => decodeRegistrationCertificateCwt(cwt, SUB)).toThrow(
      expect.objectContaining({
        issues: [expect.objectContaining({ code: 'invalid_value', path: ['payload', 'iat'] })],
      })
    )
  })

  it.each([
    ['typ is another type', new Map<number, unknown>([[RegisteredCwtHeaderClaimKey.Typ, 'rc-wrp+jwt']])],
    ['alg is a MAC algorithm', new Map<number, unknown>([[RegisteredCwtHeaderClaimKey.Algorithm, 5]])],
    ['x5chain is missing', new Map<number, unknown>([[RegisteredCwtHeaderClaimKey.X5Chain, undefined]])],
  ])('rejects a header where %s', async (_, override) => {
    const protectedHeaders = new Map<number, unknown>([
      [RegisteredCwtHeaderClaimKey.Algorithm, SignatureAlgorithm.ES256],
      [RegisteredCwtHeaderClaimKey.Typ, 'rc-wrp+cwt'],
      [RegisteredCwtHeaderClaimKey.X5Chain, new Uint8Array([1, 2, 3])],
    ])
    for (const [label, value] of override) {
      if (value === undefined) protectedHeaders.delete(label)
      else protectedHeaders.set(label, value)
    }

    const cwt = (await cwtWith({ protectedHeaders })).encode()

    expect(() => decodeRegistrationCertificateCwt(cwt, SUB)).toThrow(RegistrationCertificateValidationError)
  })

  it('rejects typ and x5chain that are only in the unprotected header', async () => {
    const cwt = (
      await cwtWith({
        protectedHeaders: new Map([[RegisteredCwtHeaderClaimKey.Algorithm, SignatureAlgorithm.ES256]]),
        unprotectedHeaders: new Map<number, unknown>([
          [RegisteredCwtHeaderClaimKey.Typ, 'rc-wrp+cwt'],
          [RegisteredCwtHeaderClaimKey.X5Chain, new Uint8Array([1, 2, 3])],
        ]),
      })
    ).encode()

    expect(() => decodeRegistrationCertificateCwt(cwt, SUB)).toThrow(RegistrationCertificateValidationError)
  })

  it('rejects a crit header', async () => {
    const protectedHeaders = new Map<number, unknown>([
      [RegisteredCwtHeaderClaimKey.Algorithm, SignatureAlgorithm.ES256],
      [RegisteredCwtHeaderClaimKey.Typ, 'rc-wrp+cwt'],
      [RegisteredCwtHeaderClaimKey.X5Chain, new Uint8Array([1, 2, 3])],
      [RegisteredCwtHeaderClaimKey.Critical, [-70_000]],
      [-70_000, true],
    ])

    const cwt = (await cwtWith({ protectedHeaders })).encode()

    expect(() => decodeRegistrationCertificateCwt(cwt, SUB)).toThrow('crit header')
  })

  it('rejects a token that is not a COSE_Sign1', () => {
    expect(() => decodeRegistrationCertificateCwt(cborEncode(new Map([['name', 'x']])), SUB)).toThrow(
      RegistrationCertificateValidationError
    )
  })
})
