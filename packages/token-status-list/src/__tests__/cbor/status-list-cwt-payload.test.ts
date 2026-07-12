import { expect, suite, test } from 'vitest'
import { StatusListCbor } from '../../cbor/status-list-cbor'
import { StatusListCwtPayload } from '../../cbor/status-list-cwt-payload'
import { StatusList } from '../../status-list'

suite('StatusListCwtPayload', () => {
  test('encode/decode', () => {
    const statusList = new StatusList(new Array(10).fill(0), 4, 'https://example.com/aggregate')
    statusList.setStatus(0, 1)
    statusList.setStatus(5, 1)

    const cborStatusList = StatusListCbor.create({
      statusList,
    })

    const payload = StatusListCwtPayload.create({
      subject: 'https://example.com/statuslists/1',
      issuedAt: new Date(1000000 * 1000),
      statusList: cborStatusList,
    })

    const encoded = payload.encode()
    const fromEncoded = StatusListCwtPayload.decode(encoded)

    expect(fromEncoded).toMatchObject(payload)
    expect(fromEncoded.timeToLive).toBeUndefined()
    expect(fromEncoded.expirationTime).toBeUndefined()
  })

  test('encode/decode with exp and ttl', () => {
    const statusList = new StatusList(new Array(10).fill(0), 4, 'https://example.com/aggregate')
    statusList.setStatus(0, 1)
    statusList.setStatus(5, 1)

    const cborStatusList = StatusListCbor.create({
      statusList,
    })

    const payload = StatusListCwtPayload.create({
      subject: 'https://example.com/statuslists/1',
      issuedAt: new Date(1000000 * 1000),
      statusList: cborStatusList,
      expirationTime: new Date(1001000 * 1000),
      timeToLive: 5,
    })

    const encoded = payload.encode()
    const fromEncoded = StatusListCwtPayload.decode(encoded)

    expect(fromEncoded).toMatchObject(payload)
    expect(fromEncoded.timeToLive).toBeDefined()
    expect(fromEncoded.expirationTime).toBeDefined()
  })

  test('encode/decode with additional claims', () => {
    const statusList = new StatusList(new Array(10).fill(0), 4, 'https://example.com/aggregate')
    statusList.setStatus(0, 1)
    statusList.setStatus(5, 1)

    const cborStatusList = StatusListCbor.create({
      statusList,
    })

    const payload = StatusListCwtPayload.create({
      subject: 'https://example.com/statuslists/1',
      issuedAt: new Date(1000000 * 1000),
      statusList: cborStatusList,
      additionalClaims: new Map([
        [1000, 'hello world'],
        [1001, 'Goodbye!'],
      ]),
    })

    const encoded = payload.encode()
    const fromEncoded = StatusListCwtPayload.decode(encoded)

    expect(fromEncoded.getCustomClaim<string>(1000)).toStrictEqual('hello world')
    expect(fromEncoded.getCustomClaim<string>(1001)).toStrictEqual('Goodbye!')

    expect(fromEncoded).toMatchObject(payload)
  })
})
