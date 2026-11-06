import { StatusListMediaTypes } from '@owf/token-status-list'
import { describe, expect, it } from 'vitest'
import {
  decodeOpenid4vpRegistrationCertificate,
  type RegistrationCertificatePayload,
  RegistrationCertificateValidationError,
  signRegistrationCertificateCwt,
  signRegistrationCertificateJwt,
  verifyRegistrationCertificate,
} from '../index'
import {
  callbacks,
  payload,
  STATUS_LIST_URI,
  SUB,
  servedAs,
  sign1Context,
  signingKey,
  signJwsCallback,
  statusListCwt,
  TEST_CERT,
} from './context.mjs'

// Between the `iat` and `exp` of the test payload
const now = new Date(1_705_000_000 * 1000)
const fetch = servedAs(await statusListCwt({ iat: 1_704_990_000 }), StatusListMediaTypes.StatusListCwt)

const signJwt = async (signed: RegistrationCertificatePayload = payload) =>
  (
    await signRegistrationCertificateJwt({
      payload: signed,
      accessCertificateSub: SUB,
      certificates: [TEST_CERT],
      signJwsCallback,
      signingTime: 1_704_000_000,
    })
  ).jws

const signCwt = async (signed: RegistrationCertificatePayload = payload) =>
  (
    await signRegistrationCertificateCwt({
      payload: signed,
      accessCertificateSub: SUB,
      certificates: [TEST_CERT],
      signingKey,
      signCoseCallback: sign1Context.sign,
    })
  ).cwt

const verify = (
  registrationCertificate: Parameters<typeof verifyRegistrationCertificate>[0]['registrationCertificate'],
  options: Partial<Parameters<typeof verifyRegistrationCertificate>[0]> = {}
) =>
  verifyRegistrationCertificate({
    registrationCertificate,
    accessCertificateSub: SUB,
    callbacks: { ...callbacks, fetch },
    now,
    ...options,
  })

describe.each([
  ['JWT', signJwt],
  ['CWT', signCwt],
])('verifyRegistrationCertificate of a %s', (_, sign) => {
  it('verifies the signature, the validity period and the status', async () => {
    const verified = await verify(await sign())

    expect(verified.payload).toStrictEqual(payload)
  })

  it('rejects a registration certificate whose signature does not verify', async () => {
    const untrusted = { ...callbacks, fetch, verifyJws: () => ({ verified: false as const }), verifyCose: () => false }

    const error = await verify(await sign(), { callbacks: untrusted }).catch((error) => error)

    expect(error).toBeInstanceOf(RegistrationCertificateValidationError)
    expect(error.findIssue('invalid_signature')).toBeDefined()
  })

  it.each([
    ['an expired', 1_710_000_100, 'expired', 'exp', 4],
    ['a not yet issued', 1_699_000_000, 'not_yet_valid', 'iat', 6],
  ] as const)('rejects %s registration certificate', async (_, at, code, name, key) => {
    const error = await verify(await sign(), { now: new Date(at * 1000) }).catch((error) => error)

    // A JWT claim by its name, a CWT claim by its key
    expect(error.findIssue(code)).toMatchObject({ path: ['payload', sign === signJwt ? name : key] })
  })

  it('rejects a registration certificate without status (REV-6.2.6.2-03)', async () => {
    const { status: _, ...withoutStatus } = payload

    const error = await verify(await sign(withoutStatus)).catch((error) => error)

    expect(error.findIssue('missing_value')).toMatchObject({
      path: ['payload', 'status'],
      requirement: 'REV-6.2.6.2-03',
    })
  })

  it('rejects a revoked registration certificate', async () => {
    const revoked = { ...payload, status: { status_list: { idx: 1, uri: STATUS_LIST_URI } } }

    const error = await verify(await sign(revoked)).catch((error) => error)

    expect(error.findIssue('revoked')).toMatchObject({ path: ['payload', 'status', 'status_list', 'idx'] })
  })
})

it('verifies what a decode function returned', async () => {
  const jws = await signJwt()
  const decoded = decodeOpenid4vpRegistrationCertificate([{ format: 'registration_cert', data: jws }], SUB)

  await expect(verify(decoded ?? jws)).resolves.toStrictEqual(decoded)
})
