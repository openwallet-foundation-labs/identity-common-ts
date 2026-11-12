import { CborStructure, TypedMap, typedMap, zUint8Array } from '@owf/cose'
import { z } from 'zod'
import { type DecompressStatusListOptions, StatusList } from '../status-list'
import type { BitsPerStatus, StatusType } from '../types'

export const zStatusListCbor = typedMap([
  ['bits', z.union([z.literal(1), z.literal(2), z.literal(4), z.literal(8)])],
  ['lst', zUint8Array],
  // NOTE: `exactOptional`, so that the key is omitted when there is no aggregation uri, rather than
  // written with an `undefined` value, which is not a valid encoding of an absent claim.
  ['aggregation_uri', z.string().exactOptional()],
])

export type StatusListCborEncodedStructure = z.input<typeof zStatusListCbor>
export type StatusListCborDecodedStructure = z.output<typeof zStatusListCbor>

export type CreateStatusListCborOptions = {
  bits: BitsPerStatus
  list: Uint8Array | number[]
  aggregationUri?: string
}

export type StatusListCborWithStatusListOptions = {
  statusList: StatusList
}

export class StatusListCbor extends CborStructure<StatusListCborEncodedStructure, StatusListCborDecodedStructure> {
  /**
   * Lazily inflated view of `lst`. The compressed bytes in the structure stay authoritative: DEFLATE
   * has no canonical form, so compressing this list again is not guaranteed to reproduce the bytes
   * we decoded (the issuer may have used a different compression level or implementation), and a
   * status list token is signed over those exact bytes.
   */
  #statusList?: StatusList

  public static override get encodingSchema() {
    return zStatusListCbor
  }

  public get bits(): BitsPerStatus {
    return this.structure.get('bits')
  }

  public get aggregationUri() {
    return this.structure.get('aggregation_uri')
  }

  /** The compressed `lst` bytes, as decoded or created, unless the status list has been modified. */
  public get compressedStatusList() {
    this.compressStatusListIfModified()
    return this.structure.get('lst')
  }

  /**
   * The status list, inflated on first read with the default `maxDecompressedBytes` of 16 MiB. A getter takes no
   * options, so {@link getStatusList} reads it with another limit.
   */
  public get statusList(): StatusList {
    return this.getStatusList()
  }

  /**
   * The status list, inflated from `lst` on the first call. `maxDecompressedBytes` limits that inflation, so pass it
   * on the first call; later calls return the same list.
   *
   * @throws StatusListValidationError with an `invalid_status_list` issue if `lst` is not a compressed status list,
   *   or inflates to more than `maxDecompressedBytes`, 16 MiB by default.
   */
  public getStatusList(options?: DecompressStatusListOptions): StatusList {
    if (!this.#statusList) {
      this.#statusList = StatusList.decompressStatusListFromBytes(
        this.structure.get('lst'),
        this.structure.get('bits'),
        this.structure.get('aggregation_uri'),
        options
      )
    }

    return this.#statusList
  }

  public setStatus(index: number, value: StatusType | number) {
    this.statusList.setStatus(index, value)
  }

  public override get encodedStructure(): StatusListCborEncodedStructure {
    this.compressStatusListIfModified()
    return super.encodedStructure
  }

  /**
   * Compress `lst` again only once the inflated list has actually been modified, so an untouched
   * status list keeps the bytes it was decoded from. `Map.set` on an existing key keeps its
   * position, so the decoded key order survives.
   */
  private compressStatusListIfModified() {
    if (!this.#statusList?.isModified) return

    this.structure.set('lst', this.#statusList.compressStatusListToBytes())
  }

  public static create(options: CreateStatusListCborOptions | StatusListCborWithStatusListOptions) {
    const structure: StatusListCborDecodedStructure = new TypedMap()

    const statusList = 'statusList' in options ? options.statusList : options

    if (statusList.aggregationUri) {
      structure.set('aggregation_uri', statusList.aggregationUri)
    }

    // Already instance of StatusList, easy to construct structure
    if (statusList instanceof StatusList) {
      structure.set('bits', statusList.getBitsPerStatus())
      structure.set('lst', statusList.compressStatusListToBytes())

      // biome-ignore lint/complexity/noThisInStatic: this.fromDecodedStructure is intentional for subclass support
      return this.fromDecodedStructure(structure)
    }

    // No StatusList instance yet
    structure.set('bits', statusList.bits)
    if (statusList.list instanceof Uint8Array) {
      // The list is already compressed. Keep the caller's bytes rather than inflating and
      // deflating them again, which would not reproduce their zlib stream. Inflate once to
      // validate that the bytes are a status list we can read back.
      StatusList.decompressStatusListFromBytes(statusList.list, statusList.bits)
      structure.set('lst', statusList.list)
    } else {
      structure.set('lst', new StatusList(statusList.list, statusList.bits).compressStatusListToBytes())
    }

    // biome-ignore lint/complexity/noThisInStatic: this.fromDecodedStructure is intentional for subclass support
    return this.fromDecodedStructure(structure)
  }
}
