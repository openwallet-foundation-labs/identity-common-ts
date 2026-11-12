import { expect, suite, test } from 'vitest'
import { StatusListCbor } from '../../cbor/status-list-cbor'
import { StatusList } from '../../status-list'

suite('StatusListCbor', () => {
  test('encode/decode from status list', () => {
    const statusList = new StatusList(new Array(10).fill(0), 4, 'https://example.com/aggregate')
    statusList.setStatus(0, 1)
    statusList.setStatus(5, 1)

    const statusListCbor = StatusListCbor.create({
      statusList,
    })

    const encoded = statusListCbor.encode()
    const fromEncoded = StatusListCbor.decode(encoded)

    expect(fromEncoded).toMatchObject(statusListCbor)
  })

  test('encode/decode from status list parts', () => {
    const statusListCbor = StatusListCbor.create({
      bits: 8,
      list: [0, 0, 0],
      aggregationUri: 'https://example.com/aggregate',
    })

    const sl = new StatusList([0, 0, 0], 8, 'foo')
    const decompressed = StatusList.decompressStatusListFromBytes(
      sl.compressStatusListToBytes(),
      sl.getBitsPerStatus(),
      sl.aggregationUri
    )
    // A decompressed list reads its statuses from its bytes until `statusList` decodes them
    expect(decompressed.statusList).toEqual(sl.statusList)
    expect(sl).toStrictEqual(decompressed)

    const encoded = statusListCbor.encode()
    const fromEncoded = StatusListCbor.decode(encoded)

    expect(fromEncoded).toMatchObject(statusListCbor)
  })

  test('encode/decode from status list compressed', () => {
    const statusListCbor = StatusListCbor.create({
      bits: 1,
      list: new Uint8Array([120, 218, 83, 100, 0, 0, 0, 68, 0, 34]),
      aggregationUri: 'https://example.com/aggregate',
    })

    const encoded = statusListCbor.encode()
    const fromEncoded = StatusListCbor.decode(encoded)

    expect(fromEncoded).toMatchObject(statusListCbor)
  })
})
