import { expect, suite, test } from 'vitest'
import { StatusListCbor } from '../../cbor/status-list-cbor'
import { StatusListCwtPayload } from '../../cbor/status-list-cwt-payload'
import { StatusList } from '../../status-list'

suite('StatusListCwtPayload', () => {
  test('defaults a missing issued at to now, however it was left out', () => {
    const statusList = StatusListCbor.create({ statusList: new StatusList(new Array(10).fill(0), 1) })

    // `iat` is required for a status list token. Passing an optional value through — which yields an
    // explicit `undefined` — has to default the same way omitting the key does.
    for (const options of [{}, { issuedAt: undefined }]) {
      const payload = StatusListCwtPayload.create({
        subject: 'https://example.com/statuslists/1',
        statusList,
        ...options,
      })

      // `iat` is a NumericDate, so the default is truncated to whole seconds
      expect(payload.issuedAt).toBeInstanceOf(Date)
      expect(Date.now() - payload.issuedAt.getTime()).toBeGreaterThanOrEqual(0)
      expect(Date.now() - payload.issuedAt.getTime()).toBeLessThan(2000)
    }
  })

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

    expect(fromEncoded.getClaim(1000)).toStrictEqual('hello world')
    expect(fromEncoded.getClaim(1001)).toStrictEqual('Goodbye!')

    expect(fromEncoded).toMatchObject(payload)
  })
})
