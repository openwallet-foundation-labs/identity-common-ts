import { base64url, concatBytes } from '@owf/identity-common'
import { deflate, deflateRaw, gzip, Inflate, inflate } from 'pako'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { StatusList } from '../status-list'
import { StatusListError } from '../status-list-error'
import { StatusType } from '../types'
import { statusListIssue } from './context'
import { statusListTestVectors } from './status-list-test-vectors'

const MiB = 1024 * 1024

afterEach(() => {
  vi.restoreAllMocks()
})

/** Counts the bytes that every `Inflate` passes to its `onData` handler. */
function countInflatedBytes() {
  const inflated = { bytes: 0 }
  const push = Inflate.prototype.push
  vi.spyOn(Inflate.prototype, 'push').mockImplementation(function (this: Inflate, ...args) {
    const onData = this.onData
    this.onData = (chunk) => {
      inflated.bytes += chunk.length
      onData.call(this, chunk)
    }
    return push.apply(this, args)
  })
  return inflated
}

/** The index and status of every status of `list` that is not Valid. */
function statusesNotValid(list: StatusList): Array<[number, number]> {
  const statuses: Array<[number, number]> = []
  for (let index = 0; index < list.totalStatuses; index++) {
    const status = list.getStatus(index)
    if (status !== StatusType.Valid) statuses.push([index, status])
  }
  return statuses
}

// A few KiB of compressed zeros inflate to a list that would exhaust the memory of whoever reads it
describe('decompressStatusListFromBytes', () => {
  it('stops inflating a list larger than 16 MiB, without inflating the rest of it', () => {
    const compressed = deflate(new Uint8Array(64 * MiB), { level: 9 })
    expect(compressed.length).toBeLessThan(128 * 1024)
    const inflated = countInflatedBytes()

    expect(() => StatusList.decompressStatusListFromBytes(compressed, 1)).toThrow(
      'The status list is larger than the maximum of 16777216 bytes'
    )
    // pako inflates in chunks of 64 KiB, so the limit is exceeded by one chunk at most
    expect(inflated.bytes).toBeGreaterThan(16 * MiB)
    expect(inflated.bytes).toBeLessThanOrEqual(16 * MiB + 64 * 1024)
  })

  it('reads a list of maxDecompressedBytes, and rejects a list of one byte more', () => {
    const options = { maxDecompressedBytes: 1000 }

    expect(
      StatusList.decompressStatusListFromBytes(deflate(new Uint8Array(1000)), 8, undefined, options)
    ).toMatchObject({ totalStatuses: 1000 })
    expect(() =>
      StatusList.decompressStatusListFromBytes(deflate(new Uint8Array(1001)), 8, undefined, options)
    ).toThrow('The status list is larger than the maximum of 1000 bytes')
  })

  it.each([Number.NaN, -1])('rejects a maxDecompressedBytes of %s before inflating', (maxDecompressedBytes) => {
    const inflated = countInflatedBytes()

    expect(() =>
      StatusList.decompressStatusListFromBytes(deflate(new Uint8Array(1)), 1, undefined, { maxDecompressedBytes })
    ).toThrow(new StatusListError(`maxDecompressedBytes must be a number of 0 or more, but is ${maxDecompressedBytes}`))
    expect(inflated.bytes).toBe(0)
  })

  // Token Status List § 4.1: the byte array is compressed with DEFLATE in the ZLIB format
  describe('of a list that is not one ZLIB stream', () => {
    const byteArray = new Uint8Array([0xb9, 0xa3])
    const decompress = (compressed: Uint8Array) => () => StatusList.decompressStatusListFromBytes(compressed, 1)

    it('reads the list in the ZLIB format', () => {
      expect(decompress(deflate(byteArray))()).toMatchObject({ totalStatuses: 16 })
    })

    it.each([
      ['gzip', gzip(byteArray)],
      ['raw DEFLATE', deflateRaw(byteArray)],
    ])('rejects the list in the %s format', (_, compressed) => {
      expect(decompress(compressed)).toThrow(statusListIssue('invalid_status_list'))
      expect(decompress(compressed)).toThrow('The status list could not be inflated: incorrect header check')
    })

    it.each([
      ['a byte', concatBytes(deflate(byteArray), new Uint8Array([0]))],
      ['a second ZLIB stream', concatBytes(deflate(byteArray), deflate(byteArray))],
    ])('rejects the list followed by %s', (_, compressed) => {
      expect(decompress(compressed)).toThrow(statusListIssue('invalid_status_list'))
      expect(decompress(compressed)).toThrow('bytes after the end of its ZLIB stream')
    })
  })

  it('reads a list of 16 MiB, 2^27 statuses at 1 bit, in the memory of its bytes', () => {
    const byteArray = new Uint8Array(16 * MiB)
    byteArray[byteArray.length - 1] = 0b1000_0000
    const compressed = deflate(byteArray, { level: 9 })

    const before = process.memoryUsage()
    const list = StatusList.decompressStatusListFromBytes(compressed, 1)
    const statuses = [list.getStatus(0), list.getStatus(2 ** 26), list.getStatus(2 ** 27 - 1)]
    const after = process.memoryUsage()

    expect(list.totalStatuses).toBe(2 ** 27)
    expect(statuses).toEqual([StatusType.Valid, StatusType.Valid, StatusType.Invalid])
    expect(() => list.getStatus(2 ** 27)).toThrow('Index out of bounds')
    // The inflated chunks and the list they are joined into. An array of 2^27 statuses would take more than 1 GiB.
    expect(after.heapUsed + after.arrayBuffers - before.heapUsed - before.arrayBuffers).toBeLessThan(64 * MiB)
  })
})

// Token Status List draft 16 Appendix C
describe.each(statusListTestVectors)('the test vector with $bits bits per status', ({ bits, lst, statuses }) => {
  const decompress = () => StatusList.decompressStatusListFromBytes(base64url.decode(lst), bits)
  const expected = statuses.filter(([, status]) => status !== StatusType.Valid).sort(([a], [b]) => a - b)

  it('reads the status at every index', () => {
    const list = decompress()

    expect(list.totalStatuses).toBe(2 ** 20)
    expect(statusesNotValid(list)).toEqual(expected)
    expect(() => list.getStatus(2 ** 20)).toThrow('Index out of bounds')
    expect(list.encodeStatusListIntoByteArray()).toEqual(inflate(base64url.decode(lst)))
  })

  it('decodes the same statuses into statusList', () => {
    const { statusList } = decompress()

    expect(statusList).toHaveLength(2 ** 20)
    expect(statusList.flatMap((status, index) => (status !== StatusType.Valid ? [[index, status]] : []))).toEqual(
      expected
    )
  })

  it('sets a status, keeping the others of its byte', () => {
    const list = decompress()
    const max = 2 ** bits - 1

    list.setStatus(1, max)

    expect(list.isModified).toBe(true)
    const changed = new Map(expected).set(1, max)
    const decompressed = StatusList.decompressStatusListFromBytes(list.compressStatusListToBytes(), bits)
    expect(statusesNotValid(decompressed)).toEqual([...changed].sort(([a], [b]) => a - b))
    expect(() => list.setStatus(2 ** 20, 0)).toThrow('Index out of bounds')
  })
})
