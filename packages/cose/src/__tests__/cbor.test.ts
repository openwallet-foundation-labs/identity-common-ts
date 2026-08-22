import { compareBytes, hex } from '@owf/identity-common'
import { Tag } from 'cbor-x'
import { describe, expect, it } from 'vitest'
import { cborDecode, cborEncode, DataItem, describeCborValue } from '../cbor'

describe('cbor', () => {
  it('should properly decode a nested map and unwrap a data item', () => {
    const decodedHex = hex.decode('d81855b9000163666f6fd8184bb90001636261726362617a')

    const decoded = cborDecode<Map<string, DataItem<Map<string, string>>>>(decodedHex, { unwrapTopLevelDataItem: true })

    expect(decoded).toBeInstanceOf(Map)
    expect(decoded.get('foo')).toBeInstanceOf(DataItem)
    expect(decoded.get('foo')?.data.get('bar')).toBe('baz')
  })

  it('should properly encoded and decoded maps (length <= 23)', () => {
    const length = 23
    const obj = Object.fromEntries(Array.from({ length }, (_, i) => [`key${i}`, i]))
    const encoded = cborEncode(DataItem.fromData(obj))
    const decoded = cborDecode(encoded, { unwrapTopLevelDataItem: false })
    const reEncode = cborEncode(decoded)
    expect(compareBytes(reEncode, encoded)).toBeTruthy()
    expect(encoded[4].toString(16)).toBe((0xa0 + length).toString(16))
  })

  it('should properly encoded and decoded maps (length >= 23)', () => {
    const length = 24
    const obj = Object.fromEntries(Array.from({ length }, (_, i) => [`key${i}`, i]))
    const encoded = cborEncode(DataItem.fromData(obj))
    const decoded = cborDecode(encoded, { unwrapTopLevelDataItem: false })
    const reEncode = cborEncode(decoded)
    expect(compareBytes(reEncode, encoded)).toBeTruthy()
    expect(encoded[4].toString(16)).toBe('b8')
    expect(encoded[5].toString(16)).toBe(length.toString(16))
  })

  it('should properly encoded and decoded maps', () => {
    const encoded = cborEncode(DataItem.fromData({ foo: 'baz' }))
    const decoded = cborDecode(encoded, { unwrapTopLevelDataItem: false })
    const reEncode = cborEncode(decoded)
    expect(compareBytes(reEncode, encoded)).toBeTruthy()
  })

  it('should properly encoded and decoded with arrays', () => {
    const encoded = cborEncode(DataItem.fromData({ foo: DataItem.fromData([1, 2, 3, 4, 5]) }))
    const decoded = cborDecode<DataItem<Map<string, DataItem<number[]>>>>(encoded, { unwrapTopLevelDataItem: false })
    expect(decoded.data.get('foo')?.data).toStrictEqual([1, 2, 3, 4, 5])
    const reEncode = cborEncode(decoded)
    expect(compareBytes(reEncode, encoded)).toBeTruthy()
  })

  it('should properly encoded and decoded with buffers', () => {
    const buffer = new Uint8Array(Buffer.from('abcdefghijk', 'utf-8'))
    const encoded = cborEncode(DataItem.fromData({ foo: DataItem.fromData(buffer) }))
    const decoded = cborDecode<DataItem<Map<string, DataItem<Uint8Array>>>>(encoded, { unwrapTopLevelDataItem: false })
    expect(decoded.data.get('foo')?.data).toBeInstanceOf(Uint8Array)
    const reEncode = cborEncode(decoded)
    expect(compareBytes(reEncode, encoded)).toBeTruthy()
  })

  it('should be able to encode/decode a DataItem', () => {
    const decodedHex = hex.decode(
      'd8185863a4686469676573744944006672616e646f6d58208798645b20ea200e19ffabac92624bee6aec63aceedecfb1b80077d22bfc20e971656c656d656e744964656e7469666965726b66616d696c795f6e616d656c656c656d656e7456616c756563446f65'
    )
    const decoded = cborDecode<unknown>(decodedHex)
    const reEncode = cborEncode(DataItem.fromData(decoded))
    expect(compareBytes(reEncode, decodedHex)).toBeTruthy()
  })
})

describe('describeCborValue', () => {
  it.each([
    ['null', null, 'null'],
    ['undefined', undefined, 'undefined'],
    ['a number', 15, "the number value '15'"],
    ['a boolean', true, "the boolean value 'true'"],
    ['a text string', 'hello', "the text string 'hello'"],
    ['an empty array', [], 'an untagged array with 0 elements'],
    ['a single element array', [1], 'an untagged array with 1 element'],
    ['an array', [1, 2, 3], 'an untagged array with 3 elements'],
    ['a single entry map', new Map([['a', 1]]), 'an untagged map with 1 entry'],
    [
      'a map',
      new Map([
        ['a', 1],
        ['b', 2],
      ]),
      'an untagged map with 2 entries',
    ],
    ['a byte string', new Uint8Array([1, 2, 3]), 'a byte string of 3 bytes'],
    ['a tagged value', new Tag([1, 2], 999), 'a CBOR value tagged with tag 999'],
    ['a data item', DataItem.fromData({ a: 1 }), 'an encoded CBOR data item (tag 24)'],
  ])('should describe %s', (_name, value, expected) => {
    expect(describeCborValue(value)).toBe(expected)
  })

  it('should truncate a long text string', () => {
    const described = describeCborValue('a'.repeat(100))

    expect(described).toBe(`the text string '${'a'.repeat(40)}…'`)
    expect(described.length).toBeLessThan(70)
  })

  it('should describe a decoded value, so a caller can tell what their input was', () => {
    expect(describeCborValue(cborDecode(cborEncode(new Map([['a', 1]]))))).toBe('an untagged map with 1 entry')
  })
})
