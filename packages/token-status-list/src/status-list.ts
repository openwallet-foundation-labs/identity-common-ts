import { deflate, inflate } from 'pako'
import { STATUS_LIST_VALIDATION_CODES, StatusListError, StatusListValidationError } from './status-list-error'
import { type BitsPerStatus, StatusType } from './types'

/**
 * A status takes exactly `bitsPerStatus` bits, so it must be an integer from 0 to 2^bitsPerStatus - 1.
 * A wider value would shift the neighbouring entries of the same byte when encoded.
 */
function assertStatusValue(value: number, bitsPerStatus: BitsPerStatus, index: number): void {
  const max = 2 ** bitsPerStatus - 1
  if (!Number.isInteger(value) || value < 0 || value > max) {
    throw new StatusListError(
      `Status value out of range at index ${index} with value ${value}, expected an integer from 0 to ${max} for ${bitsPerStatus} bits per status`
    )
  }
}

// Draft 16 § 8.3: an index outside the list must reject the Referenced Token, and NaN or a fraction would read undefined
function isIndexOf(statusList: StatusList, index: number): boolean {
  return Number.isInteger(index) && index >= 0 && index < statusList.totalStatuses
}

/**
 * Verifies that the status at `idx`, the index of a Referenced Token, is Valid (Token Status List § 8.3).
 *
 * @throws StatusListValidationError with an `index_out_of_range` or `status_not_valid` issue.
 */
export function verifyStatusValid(statusList: StatusList, idx: number): void {
  const { totalStatuses } = statusList
  if (!isIndexOf(statusList, idx)) {
    throw new StatusListValidationError('The Referenced Token is not in the status list', [
      {
        severity: 'error',
        path: [],
        code: STATUS_LIST_VALIDATION_CODES.INDEX_OUT_OF_RANGE,
        message: `Index out of bounds: ${idx} is not an index of a list of ${totalStatuses} statuses`,
        context: { idx, totalStatuses },
      },
    ])
  }

  const status = statusList.getStatus(idx)
  if (status !== StatusType.Valid) {
    throw new StatusListValidationError('The Referenced Token is not Valid', [
      {
        severity: 'error',
        path: [],
        code: STATUS_LIST_VALIDATION_CODES.STATUS_NOT_VALID,
        message: `Status for id '${idx}' is not Valid (${StatusType.Valid}), but is instead '${status}'`,
        context: { idx, status },
      },
    ])
  }
}

/**
 * StatusList is a class that manages a list of statuses with variable bit size.
 */
export class StatusList {
  private _statusList: Array<StatusType | number>
  private bitsPerStatus: BitsPerStatus
  public readonly totalStatuses: number
  public aggregationUri?: string
  #isModified = false

  constructor(statusList: number[], bitsPerStatus: BitsPerStatus, aggregationUri?: string) {
    if (![1, 2, 4, 8].includes(bitsPerStatus)) {
      throw new StatusListError('bitsPerStatus must be 1, 2, 4, or 8')
    }
    for (let i = 0; i < statusList.length; i++) {
      assertStatusValue(statusList[i], bitsPerStatus, i)
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

  /**
   * Whether the list has been modified since it was created. Holders of a compressed encoding of
   * this list use it to tell whether their bytes still represent it, without having to compress it
   * again to find out.
   */
  get isModified(): boolean {
    return this.#isModified
  }

  /** Get the status at a specific index. */
  getStatus(index: number): StatusType {
    this.assertIndex(index)
    return this._statusList[index]
  }

  /** Set the status at a specific index. */
  setStatus(index: number, value: StatusType | number): void {
    this.assertIndex(index)
    assertStatusValue(value, this.bitsPerStatus, index)
    this._statusList[index] = value
    this.#isModified = true
  }

  private assertIndex(index: number): void {
    if (!isIndexOf(this, index)) {
      throw new StatusListError(
        `Index out of bounds: ${index} is not an index of a list of ${this.totalStatuses} statuses`
      )
    }
  }

  /** Compress the status list and return as raw bytes. */
  compressStatusListToBytes(): Uint8Array {
    const byteArray = this.encodeStatusListIntoByteArray()
    return deflate(byteArray, { level: 9 })
  }

  /**
   * Decompress a raw byte array and return a new StatusList instance.
   *
   * @throws StatusListValidationError with an `invalid_status_list` issue if the bytes are not a compressed status list.
   */
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
      throw new StatusListValidationError('The status list cannot be decompressed', [
        {
          severity: 'error',
          path: [],
          code: STATUS_LIST_VALIDATION_CODES.INVALID_STATUS_LIST,
          message: `Not a status list compressed with zlib: ${err instanceof Error ? err.message : String(err)}`,
        },
      ])
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
      // The list is exposed through `statusList`, so values may have changed since construction
      assertStatusValue(status, numBits, i)
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
