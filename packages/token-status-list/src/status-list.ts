import { deflate, inflate } from 'pako'
import { SLException } from './status-list-exception'
import type { BitsPerStatus, StatusType } from './types'

/**
 * StatusList is a class that manages a list of statuses with variable bit size.
 */
export class StatusList {
  private _statusList: Array<StatusType | number>
  private bitsPerStatus: BitsPerStatus
  private totalStatuses: number
  public aggregationUri?: string

  constructor(statusList: number[], bitsPerStatus: BitsPerStatus, aggregationUri?: string) {
    if (![1, 2, 4, 8].includes(bitsPerStatus)) {
      throw new SLException('bitsPerStatus must be 1, 2, 4, or 8')
    }
    for (let i = 0; i < statusList.length; i++) {
      if (statusList[i] > 2 ** bitsPerStatus) {
        throw new SLException(`Status value out of range at index ${i} with value ${statusList[i]}`)
      }
    }
    this._statusList = statusList
    this.bitsPerStatus = bitsPerStatus
    this.totalStatuses = statusList.length
    this.aggregationUri = aggregationUri
  }

  /** Get the status list. */
  get statusList(): number[] {
    return this._statusList
  }

  /** Get the number of bits per status. */
  getBitsPerStatus(): BitsPerStatus {
    return this.bitsPerStatus
  }

  /** Get the status at a specific index. */
  getStatus(index: number): StatusType {
    if (index < 0 || index >= this.totalStatuses) {
      throw new Error('Index out of bounds')
    }
    return this._statusList[index]
  }

  /** Set the status at a specific index. */
  setStatus(index: number, value: StatusType | number): void {
    if (index < 0 || index >= this.totalStatuses) {
      throw new Error('Index out of bounds')
    }
    this._statusList[index] = value
  }

  /** Compress the status list and return as raw bytes. */
  compressStatusListToBytes(): Uint8Array {
    const byteArray = this.encodeStatusListIntoByteArray()
    return deflate(byteArray, { level: 9 })
  }

  /** Decompress a raw byte array and return a new StatusList instance. */
  static decompressStatusListFromBytes(
    compressed: Uint8Array,
    bitsPerStatus: BitsPerStatus,
    aggregationUri?: string
  ): StatusList {
    try {
      const decompressed = inflate(compressed)
      const statusList = StatusList.decodeStatusListFromByteArray(decompressed, bitsPerStatus)
      return new StatusList(statusList, bitsPerStatus, aggregationUri)
    } catch (err: unknown) {
      throw new Error(`Decompression failed: ${err}`)
    }
  }

  /** Encode the status list into a byte array. */
  public encodeStatusListIntoByteArray(): Uint8Array {
    const numBits = this.bitsPerStatus
    const numBytes = Math.ceil((this.totalStatuses * numBits) / 8)
    const byteArray = new Uint8Array(numBytes)
    let byteIndex = 0
    let bitIndex = 0
    let currentByte = ''
    for (let i = 0; i < this.totalStatuses; i++) {
      const status = this._statusList[i]
      currentByte = status.toString(2).padStart(numBits, '0') + currentByte
      bitIndex += numBits

      if (bitIndex >= 8 || i === this.totalStatuses - 1) {
        if (i === this.totalStatuses - 1 && bitIndex % 8 !== 0) {
          currentByte = currentByte.padStart(8, '0')
        }
        byteArray[byteIndex] = Number.parseInt(currentByte, 2)
        currentByte = ''
        bitIndex = 0
        byteIndex++
      }
    }

    return byteArray
  }

  /** Decode the byte array into a status list. */
  private static decodeStatusListFromByteArray(byteArray: Uint8Array, bitsPerStatus: BitsPerStatus): StatusType[] {
    const numBits = bitsPerStatus
    const totalStatuses = (byteArray.length * 8) / numBits
    const statusList = new Array<number>(totalStatuses)
    let bitIndex = 0
    for (let i = 0; i < totalStatuses; i++) {
      const byte = byteArray[Math.floor((i * numBits) / 8)]
      let byteString = byte.toString(2)
      if (byteString.length < 8) {
        byteString = '0'.repeat(8 - byteString.length) + byteString
      }
      const status = byteString.slice(bitIndex, bitIndex + numBits)
      const group = Math.floor(i / (8 / numBits))
      const indexInGroup = i % (8 / numBits)
      const position = group * (8 / numBits) + (8 / numBits + -1 - indexInGroup)
      statusList[position] = Number.parseInt(status, 2)
      bitIndex = (bitIndex + numBits) % 8
    }
    return statusList
  }
}
