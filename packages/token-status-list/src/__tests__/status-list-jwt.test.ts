import { base64url, stringToBytes } from '@owf/identity-common'
import { JoseSignatureVerificationError, JoseValidationError, signJwt } from '@owf/jose'
import { describe, expect, it, vi } from 'vitest'
import { JWT_STATUS_LIST_TYPE } from '../jwt-types'
import { StatusList } from '../status-list'
import {
  type CreateStatusListJwtPayload,
  decodeStatusListJwt,
  type SignStatusListJwtOptions,
  signStatusListJwt,
  verifyStatusListJwt,
} from '../status-list-jwt'
import { type BitsPerStatus, StatusType } from '../types'
import { jwsSigner, signJws, verifyJws } from './context'
import { signStatusListToken } from './status-list-jwt-tokens'

const uri = 'https://example.com/statuslists/1'
const iat = Math.floor(Date.now() / 1000)

const createStatusList = () => {
  const statusList = new StatusList(new Array(100).fill(StatusType.Valid), 1)
  statusList.setStatus(0, StatusType.Invalid)
  statusList.setStatus(5, StatusType.Invalid)
  return statusList
}

const signToken = async (statusList = createStatusList()) => {
  const { jwt } = await signStatusListJwt({
    statusList,
    payload: { iss: 'https://example.com', sub: uri, iat },
    signer: jwsSigner,
    signJwsCallback: signJws,
  })
  return jwt
}

const sign = (
  statusList: StatusList,
  payload: CreateStatusListJwtPayload,
  header?: SignStatusListJwtOptions['header']
) => signStatusListJwt({ statusList, payload, header, signer: jwsSigner, signJwsCallback: signJws })

describe('signStatusListJwt', () => {
  it('signs a status list token carrying the status list', async () => {
    const statusList = createStatusList()

    const { jwt, header, payload } = await sign(statusList, { sub: uri, iat })

    expect(header).toEqual({ alg: 'ES256', typ: JWT_STATUS_LIST_TYPE })
    expect(payload).toEqual({
      sub: uri,
      iat,
      status_list: { bits: 1, lst: base64url.encode(statusList.compressStatusListToBytes()) },
    })
    const verified = await verifyStatusListJwt({ jwt, uri, verifyJwsCallback: verifyJws })
    expect(verified.statusList.getStatus(0)).toBe(StatusType.Invalid)
    expect(verified.statusList.getStatus(5)).toBe(StatusType.Invalid)
  })

  it('carries the aggregation uri of the list', async () => {
    const statusList = new StatusList([0, 1], 1, 'https://example.com/aggregation')
    const { payload } = await sign(statusList, { sub: uri, iat })

    expect(payload.status_list.aggregation_uri).toBe('https://example.com/aggregation')
  })

  it('leaves out the aggregation uri when the list has none', async () => {
    const { payload } = await sign(createStatusList(), { sub: uri, iat })

    expect(Object.keys(payload.status_list)).toEqual(['bits', 'lst'])
  })

  it.each([2, 4, 8] as const)('carries a list of %i bits per status', async (bits: BitsPerStatus) => {
    const statusList = new StatusList([0, 1, 2 ** bits - 1, 0], bits)

    const { payload } = await sign(statusList, { sub: uri, iat })

    expect(payload.status_list).toEqual({ bits, lst: base64url.encode(statusList.compressStatusListToBytes()) })
  })

  it('keeps the other claims of the payload', async () => {
    const claims = { iss: 'https://example.com', sub: uri, iat, exp: iat + 3600, ttl: 300, custom: 'value' }

    const { payload } = await sign(createStatusList(), claims)

    expect(payload).toMatchObject(claims)
  })

  it('replaces a status_list claim in the payload with the list', async () => {
    const statusList = createStatusList()

    const { payload } = await sign(statusList, { sub: uri, iat, status_list: { bits: 8, lst: 'AAAA' } })

    expect(payload.status_list).toEqual({ bits: 1, lst: base64url.encode(statusList.compressStatusListToBytes()) })
  })

  it('does not change the payload and header it is given', async () => {
    const payload: CreateStatusListJwtPayload = { sub: uri, iat }
    const header = { kid: 'key-1' }

    await sign(createStatusList(), payload, header)

    expect(payload).toEqual({ sub: uri, iat })
    expect(header).toEqual({ kid: 'key-1' })
  })

  it('takes alg from the signer', async () => {
    const { header } = await sign(createStatusList(), { sub: uri, iat }, { alg: 'ES384', kid: 'key-1' })

    expect(header).toEqual({ alg: 'ES256', kid: 'key-1', typ: JWT_STATUS_LIST_TYPE })
  })

  it('signs the header and claims it returns', async () => {
    const { jwt, header, payload } = await sign(
      createStatusList(),
      { iss: 'https://example.com', sub: uri, iat, ttl: 300 },
      { kid: 'key-1' }
    )

    const decoded = decodeStatusListJwt(jwt)
    expect(decoded.header).toEqual(header)
    expect(decoded.payload).toEqual(payload)
  })

  // Draft 16 § 5.1: "The JWT type MUST be statuslist+jwt". Other forms are only accepted when verifying.
  it.each(['application/statuslist+jwt', 'StatusList+JWT', 'JWT', ''])('rejects the typ %j', async (typ) => {
    const signJwsCallback = vi.fn(signJws)

    await expect(
      signStatusListJwt({
        statusList: createStatusList(),
        payload: { sub: uri, iat },
        // @ts-expect-error typ must be statuslist+jwt
        header: { typ },
        signer: jwsSigner,
        signJwsCallback,
      })
    ).rejects.toThrow(JoseValidationError)
    expect(signJwsCallback).not.toHaveBeenCalled()
  })

  it('rejects a payload without sub', async () => {
    // @ts-expect-error sub is required
    await expect(sign(createStatusList(), { iat })).rejects.toThrow('- sub: ')
  })

  it('rejects a payload without iat', async () => {
    // @ts-expect-error iat is required
    await expect(sign(createStatusList(), { sub: uri })).rejects.toThrow('- iat: ')
  })
})

describe('decodeStatusListJwt', () => {
  it('decodes the header, payload and status list', async () => {
    const { header, payload, statusList } = decodeStatusListJwt(await signToken())

    expect(header.typ).toBe(JWT_STATUS_LIST_TYPE)
    expect(payload.sub).toBe(uri)
    expect(statusList.getStatus(0)).toBe(StatusType.Invalid)
    expect(statusList.getStatus(1)).toBe(StatusType.Valid)
    expect(statusList.getStatus(5)).toBe(StatusType.Invalid)
  })

  it('decodes the aggregation uri into the status list', async () => {
    const jwt = await signToken(new StatusList([0, 1], 1, 'https://example.com/aggregation'))

    expect(decodeStatusListJwt(jwt).statusList.aggregationUri).toBe('https://example.com/aggregation')
  })

  it('rejects a token that is not a status list token', async () => {
    const encode = (value: unknown) => base64url.encode(stringToBytes(JSON.stringify(value)))
    const [, payload, signature] = (await signToken()).split('.')

    expect(() => decodeStatusListJwt(`${encode({ alg: 'ES256', typ: 'JWT' })}.${payload}.${signature}`)).toThrow(
      JoseValidationError
    )
  })

  it('rejects a token without a status_list claim', async () => {
    const jwt = await signStatusListToken({ status_list: undefined })

    expect(() => decodeStatusListJwt(jwt)).toThrow(JoseValidationError)
    expect(() => decodeStatusListJwt(jwt)).toThrow('- status_list: ')
  })

  // The spec allows 1, 2, 4 and 8 bits per status, and nothing else
  it('rejects a status list of 3 bits per status', async () => {
    const jwt = await signStatusListToken({ status_list: { bits: 3, lst: 'eNrbuRgAAhcBXQ' } })

    expect(() => decodeStatusListJwt(jwt)).toThrow(JoseValidationError)
    expect(() => decodeStatusListJwt(jwt)).toThrow('- status_list.bits: ')
  })

  it.each([
    ['padded', 'eNrbuRgAAhcBXQ=='],
    ['standard base64', 'eNrb+/gAAhcBXQ'],
  ])('rejects a %s lst', async (_name, lst) => {
    const jwt = await signStatusListToken({ status_list: { bits: 1, lst } })

    expect(() => decodeStatusListJwt(jwt)).toThrow(JoseValidationError)
    expect(() => decodeStatusListJwt(jwt)).toThrow('- status_list.lst: ')
  })

  // Draft 16 § 5.1: "The value of the claim MUST be a positive number"
  it.each([0, -1])('rejects a ttl of %i', async (ttl) => {
    const jwt = await signStatusListToken({ ttl })

    expect(() => decodeStatusListJwt(jwt)).toThrow('- ttl: ')
  })

  it('rejects a ttl that is not a number', async () => {
    const jwt = await signStatusListToken({ ttl: '300' })

    expect(() => decodeStatusListJwt(jwt)).toThrow(JoseValidationError)
    expect(() => decodeStatusListJwt(jwt)).toThrow('- ttl: ')
  })
})

describe('verifyStatusListJwt', () => {
  it('verifies the signature and claims, and returns the status list', async () => {
    const result = await verifyStatusListJwt({ jwt: await signToken(), uri, verifyJwsCallback: verifyJws })

    expect(result.payload.sub).toBe(uri)
    expect(result.signer.alg).toBe('ES256')
    expect(result.statusList.getStatus(5)).toBe(StatusType.Invalid)
  })

  it('returns the compact token it verified', async () => {
    const jwt = await signToken()

    const { compact } = await verifyStatusListJwt({ jwt, uri, verifyJwsCallback: verifyJws })

    expect(compact).toBe(jwt)
  })

  it('accepts an already decoded token', async () => {
    const decoded = decodeStatusListJwt(await signToken())

    const { statusList } = await verifyStatusListJwt({ jwt: decoded, uri, idx: 1, verifyJwsCallback: verifyJws })

    expect(statusList.statusList).toEqual(decoded.statusList.statusList)
  })

  it('rejects a token with an invalid signature', async () => {
    const [header, payload] = (await signToken()).split('.')
    const [, , otherSignature] = (await signToken(new StatusList([0, 0], 1))).split('.')

    await expect(
      verifyStatusListJwt({ jwt: `${header}.${payload}.${otherSignature}`, uri, verifyJwsCallback: verifyJws })
    ).rejects.toThrow(JoseSignatureVerificationError)
  })

  // A JWT the issuer signed for another purpose with the same key must not be accepted as a status list
  it('rejects a token signed by the issuer whose typ header is not statuslist+jwt', async () => {
    const { payload } = await sign(createStatusList(), { sub: uri, iat })
    const { jwt } = await signJwt({ header: { typ: 'JWT' }, payload, signer: jwsSigner, signJwsCallback: signJws })
    const verifyJwsCallback = vi.fn(verifyJws)

    await expect(verifyStatusListJwt({ jwt, uri, verifyJwsCallback })).rejects.toThrow(
      `typ: typ must be statuslist+jwt (invalid_typ)`
    )
    await expect(verifyStatusListJwt({ jwt, uri, verifyJwsCallback })).rejects.toThrow(JoseValidationError)
    // the token is rejected before its signature is verified
    expect(verifyJwsCallback).not.toHaveBeenCalled()
  })

  it('accepts a token whose typ has the application/ prefix', async () => {
    const jwt = await signStatusListToken({ iat }, { typ: 'application/statuslist+jwt' })

    const { header } = await verifyStatusListJwt({ jwt, uri, verifyJwsCallback: verifyJws })

    expect(header.typ).toBe('application/statuslist+jwt')
  })

  it('rejects a token published for a different uri', async () => {
    await expect(
      verifyStatusListJwt({
        jwt: await signToken(),
        uri: 'https://example.com/other',
        verifyJwsCallback: verifyJws,
      })
    ).rejects.toThrow(`The 'sub' claim 'https://example.com/statuslists/1' does not match`)
  })

  it('rejects a token without a required claim', async () => {
    await expect(
      verifyStatusListJwt({ jwt: await signToken(), uri, requiredClaims: ['exp'], verifyJwsCallback: verifyJws })
    ).rejects.toThrow("exp: The token has no 'exp' claim, which is required (claim_missing)")
  })

  it('rejects an index whose status is not valid', async () => {
    await expect(
      verifyStatusListJwt({ jwt: await signToken(), uri, idx: 5, verifyJwsCallback: verifyJws })
    ).rejects.toThrow("Status for id '5' is not Valid")
  })
})
