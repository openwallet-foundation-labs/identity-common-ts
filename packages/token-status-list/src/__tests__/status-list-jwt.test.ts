import { base64urlEncode } from '@owf/identity-common'
import { describe, expect, it } from 'vitest'
import { JWT_STATUS_LIST_TYPE } from '../jwt-types'
import { StatusList } from '../status-list'
import { createHeaderAndPayload, getListFromStatusListJWT, getStatusListFromJWT } from '../status-list-jwt'

describe('StatusListJWT', () => {
  const listLength = 100

  it('should create a header and payload', () => {
    const statusList = new StatusList(new Array(listLength).fill(0), 1)
    statusList.setStatus(0, 1)
    statusList.setStatus(5, 1)

    const payload = {
      iss: 'https://example.com',
      sub: 'https://example.com/statuslists/1',
      iat: Math.floor(Date.now() / 1000),
    }
    const header = { alg: 'ES256', typ: '' as typeof JWT_STATUS_LIST_TYPE }

    const result = createHeaderAndPayload(statusList, payload, header)
    expect(result.header.typ).toBe(JWT_STATUS_LIST_TYPE)
    expect(result.payload.status_list).toBeDefined()
    const sl = result.payload.status_list as { bits: number; lst: string }
    expect(sl.bits).toBe(1)
    expect(typeof sl.lst).toBe('string')
  })

  it('should throw if sub is missing', () => {
    const statusList = new StatusList(new Array(listLength).fill(0), 1)
    const payload = { iss: 'https://example.com', iat: Math.floor(Date.now() / 1000) }
    const header = { alg: 'ES256', typ: '' as typeof JWT_STATUS_LIST_TYPE }

    expect(() => createHeaderAndPayload(statusList, payload, header)).toThrow('sub field is required')
  })

  it('should throw if iat is missing', () => {
    const statusList = new StatusList(new Array(listLength).fill(0), 1)
    const payload = { iss: 'https://example.com', sub: 'https://example.com/statuslists/1' }
    const header = { alg: 'ES256', typ: '' as typeof JWT_STATUS_LIST_TYPE }

    expect(() => createHeaderAndPayload(statusList, payload, header)).toThrow('iat field is required')
  })

  it('should extract status list from JWT', () => {
    const statusList = new StatusList(new Array(listLength).fill(0), 1)
    statusList.setStatus(0, 1)
    statusList.setStatus(5, 1)

    const payload = {
      iss: 'https://example.com',
      sub: 'https://example.com/statuslists/1',
      iat: Math.floor(Date.now() / 1000),
    }
    const header = { alg: 'ES256', typ: '' as typeof JWT_STATUS_LIST_TYPE }

    const result = createHeaderAndPayload(statusList, payload, header)
    const jwtString = `${base64urlEncode(JSON.stringify(result.header))}.${base64urlEncode(JSON.stringify(result.payload))}.signature`
    const decoded = getListFromStatusListJWT(jwtString)

    expect(decoded.getStatus(0)).toBe(1)
    expect(decoded.getStatus(1)).toBe(0)
    expect(decoded.getStatus(5)).toBe(1)
  })

  it('should extract status_list entry from referenced token JWT', () => {
    const referencedPayload = {
      iss: 'https://example.com',
      sub: 'user123',
      status: {
        status_list: {
          idx: 42,
          uri: 'https://example.com/statuslists/1',
        },
      },
    }
    const jwtString = `${base64urlEncode(JSON.stringify({ alg: 'ES256' }))}.${base64urlEncode(JSON.stringify(referencedPayload))}.signature`
    const entry = getStatusListFromJWT(jwtString)

    expect(entry.idx).toBe(42)
    expect(entry.uri).toBe('https://example.com/statuslists/1')
  })
})
