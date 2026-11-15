import { concatBytes, ValidationIssues } from '@owf/identity-common'
import { deflate, Inflate, type ZStream } from 'pako'
import {
  STATUS_LIST_VALIDATION_CODES,
  StatusListError,
  type StatusListValidationCode,
  type StatusListValidationContexts,
  StatusListValidationError,
} from './status-list-error'
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

type StatusListIssues = ValidationIssues<StatusListValidationCode, StatusListValidationContexts>

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
  const issues: StatusListIssues = new ValidationIssues()
  const { totalStatuses } = statusList

  if (!isIndexOf(statusList, idx)) {
    issues.add({
      code: STATUS_LIST_VALIDATION_CODES.INDEX_OUT_OF_RANGE,
      message: `Index out of bounds: ${idx} is not an index of a list of ${totalStatuses} statuses`,
      context: { idx, totalStatuses },
    })
  } else {
    const status = statusList.getStatus(idx)
    if (status !== StatusType.Valid) {
      issues.add({
        code: STATUS_LIST_VALIDATION_CODES.STATUS_NOT_VALID,
        message: `Status for id '${idx}' is not Valid (${StatusType.Valid}), but is instead '${status}'`,
        context: { idx, status },
      })
    }
  }

  if (issues.issues.length) throw new StatusListValidationError('The Referenced Token is not Valid', issues.issues)
}

/**
 * The default maximum size of a decompressed status list. A small compressed list can inflate to a list large enough
 * to exhaust the memory of whoever reads it.
 */
const DEFAULT_MAX_DECOMPRESSED_BYTES = 16 * 1024 * 1024

/** Options to decompress a status list. */
export type DecompressStatusListOptions = {
  /**
   * The maximum size in bytes a status list may inflate to, 16 MiB by default: 2^27 statuses at 1 bit per status, or
   * 2^24 at 8 bits. Inflating stops with an error once the list is larger.
   */
  maxDecompressedBytes?: number
}

/**
 * Inflate `compressed`, which must be one ZLIB stream (Token Status List § 4.1), but stop with an error once the
 * output exceeds `maxBytes`.
 */
function inflateAtMost(compressed: Uint8Array, maxBytes: number): Uint8Array {
  // With `windowBits` set, pako no longer detects and inflates a gzip stream, but only the ZLIB format
  const inflator = new Inflate({ windowBits: 15 })
  let stream: ZStream | undefined
  inflator.onStart = (strm) => {
    stream = strm
  }
  const chunks: Uint8Array[] = []
  let length = 0
  inflator.onData = (chunk) => {
    length += chunk.length
    if (length > maxBytes) {
      throw new StatusListError(`The status list is larger than the maximum of ${maxBytes} bytes`)
    }
    chunks.push(chunk)
  }
  inflator.push(compressed, true)
  if (inflator.err) throw new StatusListError(`The status list could not be inflated: ${inflator.msg}`)
  // pako stops at the end of the ZLIB stream and ignores what follows it
  if (stream?.avail_in) {
    throw new StatusListError(`The status list has ${stream.avail_in} bytes after the end of its ZLIB stream`)
  }
  return concatBytes(...chunks)
}

// Token Status List § 4.1: the statuses of a byte are counted from its least significant bit
function readStatus(byteArray: Uint8Array, bitsPerStatus: BitsPerStatus, index: number): number {
  const statusesPerByte = 8 / bitsPerStatus
  const shift = (index % statusesPerByte) * bitsPerStatus
  return (byteArray[Math.floor(index / statusesPerByte)] >> shift) & (2 ** bitsPerStatus - 1)
}

function writeStatus(byteArray: Uint8Array, bitsPerStatus: BitsPerStatus, index: number, value: number): void {
  const statusesPerByte = 8 / bitsPerStatus
  const byteIndex = Math.floor(index / statusesPerByte)
  const shift = (index % statusesPerByte) * bitsPerStatus
  byteArray[byteIndex] = (byteArray[byteIndex] & ~((2 ** bitsPerStatus - 1) << shift)) | (value << shift)
}

/**
 * StatusList is a class that manages a list of statuses with variable bit size.
 */
export class StatusList {
  // The statuses, encoded as in `lst` (Token Status List § 4.1), so a list takes no more memory than its byte array
  #byteArray: Uint8Array
  private bitsPerStatus: BitsPerStatus
  #totalStatuses: number
  public aggregationUri?: string
  #isModified = false

  constructor(statusList: readonly number[], bitsPerStatus: BitsPerStatus, aggregationUri?: string) {
    if (![1, 2, 4, 8].includes(bitsPerStatus)) {
      throw new StatusListError('bitsPerStatus must be 1, 2, 4, or 8')
    }
    this.#byteArray = new Uint8Array(Math.ceil((statusList.length * bitsPerStatus) / 8))
    for (let i = 0; i < statusList.length; i++) {
      assertStatusValue(statusList[i], bitsPerStatus, i)
      writeStatus(this.#byteArray, bitsPerStatus, i, statusList[i])
    }
    this.bitsPerStatus = bitsPerStatus
    this.#totalStatuses = statusList.length
    this.aggregationUri = aggregationUri
  }

  /** The number of statuses in the list. */
  get totalStatuses(): number {
    return this.#totalStatuses
  }

  /**
   * A copy of the status list, which takes about 8 bytes per status: to read the status of a Referenced Token, use
   * `getStatus`. Changing the copy does not change the list, which `setStatus` does.
   */
  get statusList(): readonly number[] {
    return Array.from({ length: this.#totalStatuses }, (_, index) =>
      readStatus(this.#byteArray, this.bitsPerStatus, index)
    )
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
    return readStatus(this.#byteArray, this.bitsPerStatus, index)
  }

  /** Set the status at a specific index. */
  setStatus(index: number, value: StatusType | number): void {
    this.assertIndex(index)
    assertStatusValue(value, this.bitsPerStatus, index)
    writeStatus(this.#byteArray, this.bitsPerStatus, index, value)
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
    return deflate(this.#byteArray, { level: 9 })
  }

  /**
   * Decompress a raw byte array and return a new StatusList instance, which reads its statuses from the
   * decompressed bytes.
   *
   * @throws StatusListError if `maxDecompressedBytes` is not a number of 0 or more.
   * @throws StatusListValidationError with an `invalid_status_list` issue if the bytes are not one ZLIB stream of a
   *   status list, or inflate to more than `maxDecompressedBytes`, 16 MiB by default.
   */
  static decompressStatusListFromBytes(
    compressed: Uint8Array,
    bitsPerStatus: BitsPerStatus,
    aggregationUri?: string,
    { maxDecompressedBytes = DEFAULT_MAX_DECOMPRESSED_BYTES }: DecompressStatusListOptions = {}
  ): StatusList {
    if (Number.isNaN(maxDecompressedBytes) || maxDecompressedBytes < 0) {
      throw new StatusListError(`maxDecompressedBytes must be a number of 0 or more, but is ${maxDecompressedBytes}`)
    }

    try {
      const statusList = new StatusList([], bitsPerStatus, aggregationUri)
      const byteArray = inflateAtMost(compressed, maxDecompressedBytes)
      statusList.#byteArray = byteArray
      statusList.#totalStatuses = (byteArray.length * 8) / bitsPerStatus
      return statusList
    } catch (err: unknown) {
      const issues: StatusListIssues = new ValidationIssues()
      issues.add({
        code: STATUS_LIST_VALIDATION_CODES.INVALID_STATUS_LIST,
        message: err instanceof Error ? err.message : String(err),
      })
      throw new StatusListValidationError('The status list cannot be decompressed', issues.issues)
    }
  }

  /** Encode the status list into a byte array. */
  public encodeStatusListIntoByteArray(): Uint8Array {
    return this.#byteArray.slice()
  }
}
