import { base64url, stringToBytes } from '@owf/identity-common'
import { describe, expect, it } from 'vitest'
import {
  decodeMdocRegistrationCertificate,
  decodeOpenid4vpRegistrationCertificate,
  mdocRegistrationCertificateExtension,
  openid4vpRegistrationCertificateVerifierInfo,
  RegistrationCertificateValidationError,
  signRegistrationCertificateCwt,
  signRegistrationCertificateJwt,
} from '../index'
import { payload, SUB, sign1Context, signingKey, signJwsCallback, TEST_CERT } from './context.mjs'

const { cwt } = await signRegistrationCertificateCwt({
  payload,
  accessCertificateSub: SUB,
  certificates: [TEST_CERT],
  signingKey,
  signCoseCallback: sign1Context.sign,
})

const { jws } = await signRegistrationCertificateJwt({
  payload,
  accessCertificateSub: SUB,
  certificates: [TEST_CERT],
  signJwsCallback,
})

/** Stands in for the `requestInfo` of an `ItemsRequest` of `@owf/mdoc` */
const requestInfo = (entries: Record<string, unknown>) => ({ getExtension: (key: string) => entries[key] })

describe('decodeMdocRegistrationCertificate', () => {
  it('decodes a CWT registration certificate', () => {
    const decoded = decodeMdocRegistrationCertificate(
      requestInfo({ ...mdocRegistrationCertificateExtension(cwt) }),
      SUB
    )

    expect(decoded && 'cwt' in decoded && decoded.cwt).toStrictEqual(cwt)
    expect(decoded?.payload).toStrictEqual(payload)
  })

  it('decodes a JWT registration certificate', () => {
    const decoded = decodeMdocRegistrationCertificate(requestInfo(mdocRegistrationCertificateExtension(jws)), SUB)

    expect(decoded && 'jws' in decoded && decoded.jws).toBe(jws)
  })

  it('reads the eUWrprc spelling of the ETSI TS 119 472-2 CDDL', () => {
    expect(decodeMdocRegistrationCertificate(requestInfo({ eUWrprc: cwt }), SUB)?.payload).toStrictEqual(payload)
  })

  it('returns undefined without a registration certificate', () => {
    expect(decodeMdocRegistrationCertificate(requestInfo({}), SUB)).toBeUndefined()
    expect(decodeMdocRegistrationCertificate(undefined, SUB)).toBeUndefined()
  })

  it('rejects a registration certificate that is not a byte string', () => {
    expect(() => decodeMdocRegistrationCertificate(requestInfo({ euWrprc: 'ey...' }), SUB)).toThrow(
      RegistrationCertificateValidationError
    )
  })
})

describe('decodeOpenid4vpRegistrationCertificate', () => {
  it.each([
    ['a JWT in base64url', openid4vpRegistrationCertificateVerifierInfo(jws), base64url.encode(stringToBytes(jws))],
    ['a JWT as is', openid4vpRegistrationCertificateVerifierInfo(jws, { encoding: 'compact' }), jws],
    ['a CWT in base64url', openid4vpRegistrationCertificateVerifierInfo(cwt), base64url.encode(cwt)],
  ])('creates and decodes %s', (_, element, data) => {
    expect(element).toEqual({ format: 'registration_cert', data })
    expect(decodeOpenid4vpRegistrationCertificate([element], SUB)?.payload).toStrictEqual(payload)
  })

  const verifierInfo = (data: unknown, element: Record<string, unknown> = {}) => [
    { format: 'other', data: 'ignored' },
    { format: 'registration_cert', data, ...element },
  ]

  it('decodes a CWT registration certificate in base64url', () => {
    const decoded = decodeOpenid4vpRegistrationCertificate(verifierInfo(base64url.encode(cwt)), SUB)

    expect(decoded && 'cwt' in decoded && decoded.cwt).toStrictEqual(cwt)
    expect(decoded?.payload).toStrictEqual(payload)
  })

  it.each([
    ['as its compact serialization', jws],
    ['in base64url', base64url.encode(stringToBytes(jws))],
  ])('decodes a JWT registration certificate %s', (_, data) => {
    const decoded = decodeOpenid4vpRegistrationCertificate(verifierInfo(data), SUB)

    expect(decoded && 'jws' in decoded && decoded.jws).toBe(jws)
  })

  it('returns undefined without a registration certificate', () => {
    expect(decodeOpenid4vpRegistrationCertificate([{ format: 'other', data: 'x' }], SUB)).toBeUndefined()
    expect(decodeOpenid4vpRegistrationCertificate(undefined, SUB)).toBeUndefined()
  })

  it.each([
    ['there is more than one', [...verifierInfo(jws), ...verifierInfo(jws)], 'more than one'],
    ['it has credential_ids', verifierInfo(jws, { credential_ids: ['pid'] }), 'credential_ids'],
    ['data is an object', verifierInfo({ jws }), 'must be a string'],
    ['data is not base64url', verifierInfo('not base64url!'), 'not base64url'],
  ])('rejects a registration certificate when %s', (_, info, message) => {
    expect(() => decodeOpenid4vpRegistrationCertificate(info, SUB)).toThrow(message)
  })
})
