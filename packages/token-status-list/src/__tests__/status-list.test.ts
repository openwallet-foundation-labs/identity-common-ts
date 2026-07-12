import { describe, expect, it, test } from 'vitest'
import { StatusList } from '../status-list'
import { SLException } from '../status-list-exception'
import type { BitsPerStatus } from '../types'
import { StatusType } from '../types'

describe('StatusList', () => {
  const listLength = 10000

  it('test from the example with 1 bit status', () => {
    const status: number[] = []
    status[0] = 1
    status[1] = 0
    status[2] = 0
    status[3] = 1
    status[4] = 1
    status[5] = 1
    status[6] = 0
    status[7] = 1
    status[8] = 1
    status[9] = 1
    status[10] = 0
    status[11] = 0
    status[12] = 0
    status[13] = 1
    status[14] = 0
    status[15] = 1
    const manager = new StatusList(status, 1)
    const compressed = manager.compressStatusListToBytes()
    const list = StatusList.decompressStatusListFromBytes(compressed, 1)
    for (let i = 0; i < status.length; i++) {
      expect(list.getStatus(i)).toBe(status[i])
    }

    for (let i = 0; i < list.statusList.length; i++) {
      expect(list.statusList[i]).toBe(status[i])
    }
  })

  it('test from the example with 2 bit status', () => {
    const status: number[] = []
    status[0] = 1
    status[1] = 2
    status[2] = 0
    status[3] = 3
    status[4] = 0
    status[5] = 1
    status[6] = 0
    status[7] = 1
    status[8] = 1
    status[9] = 2
    status[10] = 3
    status[11] = 3
    const manager = new StatusList(status, 2)
    const compressed = manager.compressStatusListToBytes()
    const l = StatusList.decompressStatusListFromBytes(compressed, 2)
    for (let i = 0; i < status.length; i++) {
      expect(l.getStatus(i)).toBe(status[i])
    }
  })

  describe.each([
    [1 as BitsPerStatus],
    [2 as BitsPerStatus],
    [4 as BitsPerStatus],
    [8 as BitsPerStatus],
  ])('with %i bitsPerStatus', (bitsPerStatus) => {
    let manager: StatusList

    function createList(length: number, bitsPerStatus: BitsPerStatus): number[] {
      const list: number[] = []
      for (let i = 0; i < length; i++) {
        list.push(Math.floor(Math.random() * 2 ** bitsPerStatus))
      }
      return list
    }

    it('should pass an incorrect list with wrong entries', () => {
      expect(() => {
        new StatusList([2 ** bitsPerStatus + 1], bitsPerStatus)
      }).toThrowError()
    })

    it('should compress and decompress status list correctly', () => {
      const statusList = createList(listLength, bitsPerStatus)
      manager = new StatusList(statusList, bitsPerStatus)
      const compressed = manager.compressStatusListToBytes()
      const decoded = StatusList.decompressStatusListFromBytes(compressed, bitsPerStatus)
      checkIfEqual(decoded, statusList)
    })

    it('should return the bitsPerStatus value', () => {
      const statusList = createList(listLength, bitsPerStatus as BitsPerStatus)
      manager = new StatusList(statusList, bitsPerStatus as BitsPerStatus)
      expect(manager.getBitsPerStatus()).toBe(bitsPerStatus)
    })

    it('getStatus returns the correct status', () => {
      const statusList = createList(listLength, bitsPerStatus as BitsPerStatus)
      manager = new StatusList(statusList, bitsPerStatus as BitsPerStatus)

      for (let i = 0; i < statusList.length; i++) {
        expect(manager.getStatus(i)).toBe(statusList[i])
      }
    })

    it('setStatus sets the correct status', () => {
      const statusList = createList(listLength, bitsPerStatus as BitsPerStatus)
      manager = new StatusList(statusList, bitsPerStatus as BitsPerStatus)

      const newValue = Math.floor(Math.random() * 2 ** bitsPerStatus)
      manager.setStatus(0, newValue)
      expect(manager.getStatus(0)).toBe(newValue)
    })

    it('getStatus throws an error for out of bounds index', () => {
      const statusList = createList(listLength, bitsPerStatus as BitsPerStatus)
      manager = new StatusList(statusList, bitsPerStatus as BitsPerStatus)

      expect(() => manager.getStatus(-1)).toThrow('Index out of bounds')
      expect(() => manager.getStatus(listLength)).toThrow('Index out of bounds')
    })

    it('setStatus throws an error for out of bounds index', () => {
      const statusList = createList(listLength, bitsPerStatus as BitsPerStatus)
      manager = new StatusList(statusList, bitsPerStatus as BitsPerStatus)

      expect(() => manager.setStatus(-1, 5)).toThrow('Index out of bounds')
      expect(() => manager.setStatus(listLength, 6)).toThrow('Index out of bounds')
    })

    it('decompressStatusListFromBytes throws an error when decompression fails', () => {
      expect(() => StatusList.decompressStatusListFromBytes(new Uint8Array([0, 1, 2, 3]), bitsPerStatus)).toThrowError()
    })

    test('encodeStatusList covers remaining bits in last byte', () => {
      const totalStatuses = 10
      const statusList = Array(totalStatuses).fill(0)
      const manager = new StatusList(statusList, 1)
      const compressed = manager.compressStatusListToBytes()
      const decoded = StatusList.decompressStatusListFromBytes(compressed, 1)
      checkIfEqual(decoded, statusList)
    })

    function checkIfEqual(statusList1: StatusList, rawStatusList: number[]) {
      for (let i = 0; i < rawStatusList.length; i++) {
        expect(statusList1.getStatus(i)).toBe(rawStatusList[i])
      }
    }

    describe('constructor', () => {
      test.each<[number]>([
        [3],
        [5],
        [6],
        [7],
        [9],
        [10],
      ])('throws an error for invalid bitsPerStatus value (%i)', (bps) => {
        expect(() => {
          new StatusList([], bps as BitsPerStatus)
        }).toThrow('bitsPerStatus must be 1, 2, 4, or 8')
      })

      test.each<[BitsPerStatus]>([
        [1],
        [2],
        [4],
        [8],
      ])('does not throw an error for valid bitsPerStatus value (%i)', (bps) => {
        expect(() => {
          new StatusList([], bps)
        }).not.toThrow()
      })
    })
  })

  describe('SLException', () => {
    it('should create exception with message', () => {
      const err = new SLException('test error')
      expect(err.message).toBe('test error')
      expect(err.name).toBe('SLException')
    })

    it('should create exception with details', () => {
      const err = new SLException('test error', { code: 42 })
      expect(err.details).toEqual({ code: 42 })
      expect(err.getFullMessage()).toContain('42')
    })
  })

  describe('StatusTypes', () => {
    it('should have correct status type values per spec', () => {
      expect(StatusType.Valid).toBe(0x00)
      expect(StatusType.Invalid).toBe(0x01)
      expect(StatusType.Suspended).toBe(0x02)
      expect(StatusType.ApplicationSpecific3).toBe(0x03)
    })
  })

  describe('Spec compliance - byte encoding', () => {
    it('should match spec example for 1-bit status list', () => {
      const statuses = new Array(16).fill(0)
      statuses[0] = 1
      statuses[3] = 1
      statuses[4] = 1
      statuses[5] = 1
      statuses[7] = 1
      statuses[8] = 1
      statuses[9] = 1
      statuses[13] = 1
      statuses[15] = 1

      const list = new StatusList(statuses, 1)
      const encoded = list.encodeStatusListIntoByteArray()

      expect(encoded[0]).toBe(0xb9)
      expect(encoded[1]).toBe(0xa3)
    })
  })
})
