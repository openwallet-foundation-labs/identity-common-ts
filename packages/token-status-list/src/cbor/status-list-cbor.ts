import { CborStructure, TypedMap, typedMap, zUint8Array } from '@owf/cose'
import { z } from 'zod'
import { StatusList } from '../status-list'
import type { BitsPerStatus } from '../types'

export const statusListCborEncodedSchema = typedMap([
  ['bits', z.union([z.literal(1), z.literal(2), z.literal(4), z.literal(8)])],
  ['lst', zUint8Array],
  ['aggregation_uri', z.string().optional()],
])

export const statusListCborDecodedSchema = z.instanceof(StatusList)

export type StatusListCborEncodedStructure = z.infer<typeof statusListCborEncodedSchema>
export type StatusListCborDecodedStructure = z.infer<typeof statusListCborDecodedSchema>

export type CreateStatusListCborOptions = {
  bits: BitsPerStatus
  list: Uint8Array | number[]
  aggregationUri?: string
}

export type StatusListCborWithStatusListOptions = {
  statusList: StatusList
}

export class StatusListCbor extends CborStructure<StatusListCborEncodedStructure, StatusListCborDecodedStructure> {
  public statusList = this.structure

  public static override get encodingSchema() {
    return z.codec(statusListCborEncodedSchema, statusListCborDecodedSchema, {
      encode: (statusList) => {
        return new TypedMap([
          ['bits', statusList.getBitsPerStatus()],
          ['lst', statusList.compressStatusListToBytes()],
          ['aggregation_uri', statusList.aggregationUri],
        ]) satisfies StatusListCborEncodedStructure
      },
      decode: (input) => {
        return StatusList.decompressStatusListFromBytes(
          input.get('lst'),
          input.get('bits'),
          input.get('aggregation_uri')
        )
      },
    })
  }

  public static create(options: CreateStatusListCborOptions | StatusListCborWithStatusListOptions) {
    const statusList =
      'statusList' in options
        ? options.statusList
        : options.list instanceof Uint8Array
          ? StatusList.decompressStatusListFromBytes(options.list, options.bits, options.aggregationUri)
          : new StatusList(options.list, options.bits, options.aggregationUri)

    return new StatusListCbor(statusList)
  }
}
