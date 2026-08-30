import {
  type CreateCwtPayloadOptions,
  CwtPayload,
  cwtPayloadClaimsFromOptions,
  extendCwtPayloadClaims,
  RegisteredCwtClaimKey,
  TypedMap,
} from '@owf/cose'
import z from 'zod'
import type { StatusList } from '../status-list'
import { StatusListCbor, type StatusListCborEncodedStructure } from './status-list-cbor'

export enum StatusListCwtClaimKey {
  TimeToLive = 65534,
  StatusList = 65533,
}

/**
 * The registered CWT claims, with the ones a status list CWT requires narrowed to non-optional, plus
 * the status list specific claims.
 *
 * @see https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-13.html#name-status-list-token-in-cwt-fo
 */
const statusListCwtPayloadSchema = extendCwtPayloadClaims(
  [
    [RegisteredCwtClaimKey.Subject, z.string()],
    [RegisteredCwtClaimKey.IssuedAt, z.number()],
    [StatusListCwtClaimKey.TimeToLive, z.number().exactOptional()],
    [StatusListCwtClaimKey.StatusList, z.instanceof(StatusListCbor)],
  ] as const,
  { keyLabels: StatusListCwtClaimKey }
)

export type StatusListCwtPayloadEncodedStructure = z.infer<typeof statusListCwtPayloadSchema>
export type StatusListCwtPayloadDecodedStructure = z.infer<typeof statusListCwtPayloadSchema>

export type CreateStatusListCwtPayloadOptions = CreateCwtPayloadOptions & {
  subject: string
  statusList: StatusListCbor | StatusList
  timeToLive?: number
}

export class StatusListCwtPayload extends CwtPayload<StatusListCwtPayloadDecodedStructure> {
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

  public static override create(options: CreateStatusListCwtPayloadOptions) {
    // `iat` is required for a status list token, so it defaults to now rather than being omitted.
    const claims = cwtPayloadClaimsFromOptions({ issuedAt: new Date(), ...options })

    claims.set(
      StatusListCwtClaimKey.StatusList,
      options.statusList instanceof StatusListCbor
        ? options.statusList
        : StatusListCbor.create({ statusList: options.statusList })
    )

    if (options.timeToLive !== undefined) {
      claims.set(StatusListCwtClaimKey.TimeToLive, options.timeToLive)
    }

    return StatusListCwtPayload.fromDecodedStructure(TypedMap.fromMap(claims))
  }

  /** `ttl` (65534), in seconds. */
  public get timeToLive() {
    return this.getClaim(StatusListCwtClaimKey.TimeToLive)
  }

  /** `status_list` (65533) */
  public get statusList(): StatusList {
    return this.getClaim(StatusListCwtClaimKey.StatusList).statusList
  }

  public setStatusList(statusList: StatusList | StatusListCbor) {
    this.claims.set(
      StatusListCwtClaimKey.StatusList,
      statusList instanceof StatusListCbor ? statusList : StatusListCbor.create({ statusList })
    )
  }
}
