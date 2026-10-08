import { base64url, stringToBytes } from '@owf/identity-common'
import { JoseSignatureVerificationError, JoseValidationError, signJwt } from '@owf/jose'
import { describe, expect, it, vi } from 'vitest'
import { JWT_STATUS_LIST_TYPE } from '../jwt-types'
import { StatusList } from '../status-list'
import {
  type CreateStatusListJwtHeader,
  type CreateStatusListJwtPayload,
  createHeaderAndPayload,
  decodeStatusListJwt,
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

describe('createHeaderAndPayload', () => {
  it('creates a header and payload carrying the status list', () => {
    const statusList = createStatusList()

    const { header, payload } = createHeaderAndPayload(statusList, { sub: uri, iat }, { alg: 'ES256' })

    expect(header).toEqual({ alg: 'ES256', typ: JWT_STATUS_LIST_TYPE })
    expect(payload).toEqual({
      sub: uri,
      iat,
      status_list: { bits: 1, lst: base64url.encode(statusList.compressStatusListToBytes()) },
    })
  })

  it('carries the aggregation uri of the list', () => {
    const statusList = new StatusList([0, 1], 1, 'https://example.com/aggregation')
    const { payload } = createHeaderAndPayload(statusList, { sub: uri, iat }, { alg: 'ES256' })

    expect(payload.status_list.aggregation_uri).toBe('https://example.com/aggregation')
  })

  it('leaves out the aggregation uri when the list has none', () => {
    const { payload } = createHeaderAndPayload(createStatusList(), { sub: uri, iat }, { alg: 'ES256' })

    expect(Object.keys(payload.status_list)).toEqual(['bits', 'lst'])
  })

  it.each([2, 4, 8] as const)('carries a list of %i bits per status', (bits: BitsPerStatus) => {
    const statusList = new StatusList([0, 1, 2 ** bits - 1, 0], bits)

    const { payload } = createHeaderAndPayload(statusList, { sub: uri, iat }, { alg: 'ES256' })

    expect(payload.status_list).toEqual({ bits, lst: base64url.encode(statusList.compressStatusListToBytes()) })
  })

  it('keeps the other claims of the payload', () => {
    const claims = { iss: 'https://example.com', sub: uri, iat, exp: iat + 3600, ttl: 300, custom: 'value' }

    const { payload } = createHeaderAndPayload(createStatusList(), claims, { alg: 'ES256' })

    expect(payload).toMatchObject(claims)
  })

  it('replaces a status_list claim in the payload with the list', () => {
    const statusList = createStatusList()
    const payload: CreateStatusListJwtPayload = { sub: uri, iat, status_list: { bits: 8, lst: 'AAAA' } }

    const created = createHeaderAndPayload(statusList, payload, { alg: 'ES256' })

    expect(created.payload.status_list).toEqual({
      bits: 1,
      lst: base64url.encode(statusList.compressStatusListToBytes()),
    })
  })

  it('does not change the payload it is given', () => {
    const payload: CreateStatusListJwtPayload = { sub: uri, iat }

    createHeaderAndPayload(createStatusList(), payload, { alg: 'ES256' })

    expect(payload).toEqual({ sub: uri, iat })
  })

  it('does not change the header it is given', () => {
    const header: CreateStatusListJwtHeader = { alg: 'ES256' }

    createHeaderAndPayload(createStatusList(), { sub: uri, iat }, header)

    expect(header).toEqual({ alg: 'ES256' })
  })

  // RFC 7515 section 4.1.9: `typ` may carry the media type with its `application/` prefix
  it('keeps a typ with the application/ prefix as it is given', () => {
    const { header } = createHeaderAndPayload(
      createStatusList(),
      { sub: uri, iat },
      { alg: 'ES256', typ: 'application/statuslist+jwt' }
    )

    expect(header.typ).toBe('application/statuslist+jwt')
  })

  it('rejects a typ that is not the status list type', () => {
    expect(() => createHeaderAndPayload(createStatusList(), { sub: uri, iat }, { alg: 'ES256', typ: 'JWT' })).toThrow(
      'Unable to create the status list token, invalid header'
    )
  })

  // Earlier versions set the typ whatever was passed, and their README passed an empty one
  it('rejects an empty typ rather than replacing it', () => {
    const create = () => createHeaderAndPayload(createStatusList(), { sub: uri, iat }, { alg: 'ES256', typ: '' })

    expect(create).toThrow(JoseValidationError)
    expect(create).toThrow(`Expected the media type to be 'statuslist+jwt' at "typ"`)
  })

  it('rejects a payload without sub', () => {
    // @ts-expect-error sub is required
    const create = () => createHeaderAndPayload(createStatusList(), { iat }, { alg: 'ES256' })

    expect(create).toThrow(JoseValidationError)
    expect(create).toThrow('at "sub"')
  })

  it('rejects a payload without iat', () => {
    // @ts-expect-error iat is required
    const create = () => createHeaderAndPayload(createStatusList(), { sub: uri }, { alg: 'ES256' })

    expect(create).toThrow(JoseValidationError)
    expect(create).toThrow('at "iat"')
  })
})

describe('signStatusListJwt', () => {
  it('signs a status list token carrying the status list', async () => {
    const { jwt, header, payload } = await signStatusListJwt({
      statusList: createStatusList(),
      payload: { sub: uri, iat },
      signer: jwsSigner,
      signJwsCallback: signJws,
    })

    expect(header).toEqual({ alg: 'ES256', typ: JWT_STATUS_LIST_TYPE })
    expect(payload.sub).toBe(uri)

    const { statusList } = await verifyStatusListJwt({ jwt, uri, verifyJwsCallback: verifyJws })
    expect(statusList.getStatus(0)).toBe(StatusType.Invalid)
    expect(statusList.getStatus(5)).toBe(StatusType.Invalid)
  })

  it('takes alg from the signer', async () => {
    const { header } = await signStatusListJwt({
      statusList: createStatusList(),
      payload: { sub: uri, iat },
      header: { alg: 'ES384', kid: 'key-1' },
      signer: jwsSigner,
      signJwsCallback: signJws,
    })

    expect(header).toEqual({ alg: 'ES256', kid: 'key-1', typ: JWT_STATUS_LIST_TYPE })
  })

  it('signs the header and claims it returns', async () => {
    const { jwt, header, payload } = await signStatusListJwt({
      statusList: createStatusList(),
      payload: { iss: 'https://example.com', sub: uri, iat, ttl: 300 },
      header: { kid: 'key-1' },
      signer: jwsSigner,
      signJwsCallback: signJws,
    })

    const decoded = decodeStatusListJwt(jwt)
    expect(decoded.header).toEqual(header)
    expect(decoded.payload).toEqual(payload)
  })

  it('keeps a typ with the application/ prefix', async () => {
    const { jwt } = await signStatusListJwt({
      statusList: createStatusList(),
      payload: { sub: uri, iat },
      header: { typ: 'application/statuslist+jwt' },
      signer: jwsSigner,
      signJwsCallback: signJws,
    })

    expect(decodeStatusListJwt(jwt).header.typ).toBe('application/statuslist+jwt')
  })

  it('rejects a typ that is not the status list type', async () => {
    await expect(
      signStatusListJwt({
        statusList: createStatusList(),
        payload: { sub: uri, iat },
        header: { typ: 'JWT' },
        signer: jwsSigner,
        signJwsCallback: signJws,
      })
    ).rejects.toThrow(JoseValidationError)
  })

  it('does not sign a payload without iat', async () => {
    const signJwsCallback = vi.fn(signJws)

    await expect(
      // @ts-expect-error iat is required
      signStatusListJwt({ statusList: createStatusList(), payload: { sub: uri }, signer: jwsSigner, signJwsCallback })
    ).rejects.toThrow(JoseValidationError)
    expect(signJwsCallback).not.toHaveBeenCalled()
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
    expect(() => decodeStatusListJwt(jwt)).toThrow('at "status_list"')
  })

  // The spec allows 1, 2, 4 and 8 bits per status, and nothing else
  it('rejects a status list of 3 bits per status', async () => {
    const jwt = await signStatusListToken({ status_list: { bits: 3, lst: 'eNrbuRgAAhcBXQ' } })

    expect(() => decodeStatusListJwt(jwt)).toThrow(JoseValidationError)
    expect(() => decodeStatusListJwt(jwt)).toThrow('at "status_list.bits"')
  })

  it.each([
    ['padded', 'eNrbuRgAAhcBXQ=='],
    ['standard base64', 'eNrb+/gAAhcBXQ'],
  ])('rejects a %s lst', async (_name, lst) => {
    const jwt = await signStatusListToken({ status_list: { bits: 1, lst } })

    expect(() => decodeStatusListJwt(jwt)).toThrow(JoseValidationError)
    expect(() => decodeStatusListJwt(jwt)).toThrow('at "status_list.lst"')
  })

  it('rejects a ttl that is not a number', async () => {
    const jwt = await signStatusListToken({ ttl: '300' })

    expect(() => decodeStatusListJwt(jwt)).toThrow(JoseValidationError)
    expect(() => decodeStatusListJwt(jwt)).toThrow('at "ttl"')
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
    const { payload } = createHeaderAndPayload(createStatusList(), { sub: uri, iat }, { alg: 'ES256' })
    const { jwt } = await signJwt({ header: { typ: 'JWT' }, payload, signer: jwsSigner, signJwsCallback: signJws })
    const verifyJwsCallback = vi.fn(verifyJws)

    await expect(verifyStatusListJwt({ jwt, uri, verifyJwsCallback })).rejects.toThrow(
      `Expected the media type to be 'statuslist+jwt' at "typ"`
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
    ).rejects.toThrow("The token has no 'exp' claim, which is required.")
  })

  it('rejects an index whose status is not valid', async () => {
    await expect(
      verifyStatusListJwt({ jwt: await signToken(), uri, idx: 5, verifyJwsCallback: verifyJws })
    ).rejects.toThrow("Status for id '5' is not Valid")
  })
})
