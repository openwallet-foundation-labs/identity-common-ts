import { CborStructure, RegisteredCwtClaimKey, TypedMap, typedMap } from '@owf/cose'
import z from 'zod'
import type { StatusList } from '../status-list'
import { StatusListCbor, type StatusListCborEncodedStructure } from './status-list-cbor'

export enum StatusListCwtClaimKey {
  TimeToLive = 65534,
  StatusList = 65533,
}

const statusListCwtPayloadSchema = typedMap(
  [
    [RegisteredCwtClaimKey.Subject, z.string()],
    [RegisteredCwtClaimKey.IssuedAt, z.number()],
    [RegisteredCwtClaimKey.ExpirationTime, z.number().exactOptional()],
    [StatusListCwtClaimKey.TimeToLive, z.number().exactOptional()],
    [StatusListCwtClaimKey.StatusList, z.instanceof(StatusListCbor)],
  ],
  { allowAdditionalKeys: true }
)

export type StatusListCwtPayloadEncodedStructure = z.infer<typeof statusListCwtPayloadSchema>
export type StatusListCwtPayloadDecodedStructure = z.infer<typeof statusListCwtPayloadSchema>

export type CreateStatusListCwtPayloadOptions = {
  subject: string
  statusList: StatusListCbor | StatusList
  issuedAt?: Date
  expirationTime?: Date
  timeToLive?: number
  additionalClaims?: Map<number | string, unknown>
}

export class StatusListCwtPayload extends CborStructure<
  StatusListCwtPayloadEncodedStructure,
  StatusListCwtPayloadDecodedStructure
> {
  public static override get encodingSchema() {
    return z.codec(statusListCwtPayloadSchema.in, statusListCwtPayloadSchema.out, {
      decode: (input) => {
        const map: StatusListCwtPayloadDecodedStructure = TypedMap.fromMap(input)

        map.set(
          StatusListCwtClaimKey.StatusList,
          StatusListCbor.fromEncodedStructure(
            input.get(StatusListCwtClaimKey.StatusList) as StatusListCborEncodedStructure
          )
        )

        return map
      },
      encode: (output) => {
        const map = output.toMap() as Map<unknown, unknown>
        map.set(StatusListCwtClaimKey.StatusList, output.get(StatusListCwtClaimKey.StatusList).encodedStructure)
        return map
      },
    })
  }

  public static create(options: CreateStatusListCwtPayloadOptions) {
    const map = new TypedMap([
      [RegisteredCwtClaimKey.Subject, options.subject],
      [RegisteredCwtClaimKey.IssuedAt, Math.floor((options.issuedAt?.getTime() ?? Date.now()) / 1000)],
      [
        StatusListCwtClaimKey.StatusList,
        options.statusList instanceof StatusListCbor
          ? options.statusList
          : StatusListCbor.create({ statusList: options.statusList }),
      ],
      ...(options.additionalClaims ?? new Map()).entries(),
    ]) satisfies StatusListCwtPayloadEncodedStructure

    if (options.expirationTime) {
      map.set(RegisteredCwtClaimKey.ExpirationTime, Math.floor(options.expirationTime.getTime() / 1000))
    }

    if (options.timeToLive) {
      map.set(StatusListCwtClaimKey.TimeToLive, options.timeToLive)
    }

    return new StatusListCwtPayload(statusListCwtPayloadSchema.parse(map.toMap()))
  }

  public get subject() {
    return this.structure.get(RegisteredCwtClaimKey.Subject)
  }

  public get issuedAt() {
    return new Date(this.structure.get(RegisteredCwtClaimKey.IssuedAt) * 1000)
  }

  public get expirationTime() {
    return this.structure.has(RegisteredCwtClaimKey.ExpirationTime)
      ? // biome-ignore lint/style/noNonNullAssertion: checked with `has` in the line above
        new Date(this.structure.get(RegisteredCwtClaimKey.ExpirationTime)! * 1000)
      : undefined
  }

  public get timeToLive() {
    return this.structure.get(StatusListCwtClaimKey.TimeToLive)
  }

  public get statusList() {
    return this.structure.get(StatusListCwtClaimKey.StatusList).statusList
  }

  public getCustomClaim<ClaimType = unknown>(key: number) {
    return this.structure.get(key) as ClaimType | unknown
  }

  public setStatusList(statusList: StatusList | StatusListCbor) {
    this.structure.set(
      StatusListCwtClaimKey.StatusList,
      statusList instanceof StatusListCbor ? statusList : StatusListCbor.create({ statusList })
    )
  }
}
