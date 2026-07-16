import { cborDecode, cborEncode } from '@owf/cose'
import { deflate } from 'pako'
import { expect, suite, test } from 'vitest'
import { StatusListCbor } from '../../cbor/status-list-cbor'
import { StatusList } from '../../status-list'

/**
 * A status list as some other issuer would send it: `lst` compressed at the zlib default level
 * (`78 9c`) rather than at level 9 (`78 da`), which is what this library compresses at.
 */
const foreignStatusList = (entries: Array<[string, unknown]>) => cborEncode(new Map(entries))

const hex = (bytes: Uint8Array) => Buffer.from(bytes).toString('hex')

const defaultLevelLst = deflate(new StatusList([0, 1, 0, 1, 0, 0, 0, 0], 1).encodeStatusListIntoByteArray())

suite('StatusListCbor round trip', () => {
  test('re-encodes a foreign status list to the exact bytes it was decoded from', () => {
    // Guards the actual reported bug: the issuer signed over `78 9c`, so re-compressing at level 9
    // would produce `78 da` and invalidate their signature.
    expect(hex(defaultLevelLst.slice(0, 2))).toBe('789c')

    const original = foreignStatusList([
      ['bits', 1],
      ['lst', defaultLevelLst],
      ['aggregation_uri', 'https://example.com/aggregate'],
    ])

    expect(hex(StatusListCbor.decode(original).encode())).toEqual(hex(original))
  })

  test('preserves the key order it decoded, rather than imposing its own', () => {
    const original = foreignStatusList([
      ['aggregation_uri', 'https://example.com/aggregate'],
      ['lst', defaultLevelLst],
      ['bits', 1],
    ])

    expect(hex(StatusListCbor.decode(original).encode())).toEqual(hex(original))
  })

  test('reading the status list does not disturb the compressed bytes', () => {
    const statusListCbor = StatusListCbor.decode(
      foreignStatusList([
        ['bits', 1],
        ['lst', defaultLevelLst],
      ])
    )

    expect(statusListCbor.statusList.getStatus(1)).toBe(1)
    expect(hex(statusListCbor.compressedStatusList)).toEqual(hex(defaultLevelLst))
  })

  test('decodes a status list that omits aggregation_uri', () => {
    const statusListCbor = StatusListCbor.decode(
      foreignStatusList([
        ['bits', 1],
        ['lst', defaultLevelLst],
      ])
    )

    expect(statusListCbor.aggregationUri).toBeUndefined()
    expect(statusListCbor.statusList.statusList.slice(0, 4)).toEqual([0, 1, 0, 1])
  })

  test('rejects a status list that encodes aggregation_uri as undefined', () => {
    // Emitted by this library up to and including 0.3.1, but not a valid encoding of an absent
    // claim, so it is rejected rather than accommodated.
    expect(() =>
      StatusListCbor.decode(
        foreignStatusList([
          ['bits', 1],
          ['lst', defaultLevelLst],
          ['aggregation_uri', undefined],
        ])
      )
    ).toThrow('Error decoding StatusListCbor')
  })

  test('omits aggregation_uri entirely when it is not set', () => {
    const encoded = StatusListCbor.create({ bits: 1, list: [0, 1, 0] }).encode()

    expect(Array.from(cborDecode<Map<string, unknown>>(encoded).keys())).toEqual(['bits', 'lst'])
  })

  test('keeps already compressed bytes passed to create as they are', () => {
    const statusListCbor = StatusListCbor.create({ bits: 1, list: defaultLevelLst })

    expect(hex(statusListCbor.compressedStatusList)).toEqual(hex(defaultLevelLst))
  })

  test('rejects bytes passed to create that are not a compressed status list', () => {
    expect(() => StatusListCbor.create({ bits: 1, list: new Uint8Array([0, 1, 2, 3]) })).toThrow('Decompression failed')
  })

  suite('after modification', () => {
    test('compresses again when modified through the status list cbor', () => {
      const statusListCbor = StatusListCbor.decode(
        foreignStatusList([
          ['bits', 1],
          ['lst', defaultLevelLst],
        ])
      )

      statusListCbor.setStatus(0, 1)

      expect(hex(statusListCbor.compressedStatusList)).not.toEqual(hex(defaultLevelLst))
      expect(StatusListCbor.decode(statusListCbor.encode()).statusList.statusList.slice(0, 4)).toEqual([1, 1, 0, 1])
    })

    test('compresses again when modified through the inflated status list', () => {
      const statusListCbor = StatusListCbor.decode(
        foreignStatusList([
          ['bits', 1],
          ['lst', defaultLevelLst],
        ])
      )

      statusListCbor.statusList.setStatus(0, 1)

      expect(StatusListCbor.decode(statusListCbor.encode()).statusList.statusList.slice(0, 4)).toEqual([1, 1, 0, 1])
    })
  })
})
