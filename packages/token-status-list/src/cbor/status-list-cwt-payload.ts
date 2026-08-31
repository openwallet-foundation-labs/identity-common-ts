import {
  type CreateCwtPayloadOptions,
  CwtClaimVerificationError,
  CwtPayload,
  cwtPayloadClaimsFromOptions,
  extendCwtPayloadClaims,
  RegisteredCwtClaimKey,
  TypedMap,
  type VerifyCwtClaimsOptions,
} from '@owf/cose'
import z from 'zod'
import type { StatusList } from '../status-list'
import { SLException } from '../status-list-exception'
import { StatusType } from '../types'
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

/**
 * The options {@link StatusListCwtPayload.verifyClaims} takes: the generic CWT ones, with `sub`
 * replaced by the `uri` it has to be equal to.
 */
export type VerifyStatusListCwtClaimsOptions = Omit<VerifyCwtClaimsOptions, 'expectedSubject' | 'keyLabels'> & {
  /** The `uri` of the status list reference the token was fetched for, which `sub` must equal. */
  uri: string
}

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
    // NOTE: applied after the spread, so that an explicit `issuedAt: undefined` — what passing
    // through an optional value gives — defaults the same way omitting the key does.
    const claims = cwtPayloadClaimsFromOptions({ ...options, issuedAt: options.issuedAt ?? new Date() })

    claims.set(
      StatusListCwtClaimKey.StatusList,
      options.statusList instanceof StatusListCbor
        ? options.statusList
        : StatusListCbor.create({ statusList: options.statusList })
    )

    if (options.timeToLive !== undefined) {
      claims.set(StatusListCwtClaimKey.TimeToLive, options.timeToLive)
    }

    // biome-ignore lint/complexity/noThisInStatic: this.fromDecodedStructure is intentional for subclass support
    return this.fromDecodedStructure(TypedMap.fromMap(claims))
  }

  /** `ttl` (65534), in seconds. */
  public get timeToLive() {
    return this.getClaim(StatusListCwtClaimKey.TimeToLive)
  }

  /** `status_list` (65533) */
  public get statusList(): StatusList {
    return this.getClaim(StatusListCwtClaimKey.StatusList).statusList
  }

  /**
   * Verifies the claims of a Status List Token, on top of the generic CWT ones: `sub` and `iat` are
   * REQUIRED, and `sub` has to match the URI the token was referenced by — without that check a
   * token published for one URI can be replayed for another under the same issuer.
   *
   * A profile that makes a further claim mandatory — ISO/IEC 18013-5 second edition § 12.3.6.3 does
   * for `exp`, on the revocation list of an MSO — adds it through `requiredClaims`.
   *
   * @throws SLException if a required claim is missing, `sub` is not the referenced URI, or the
   *   token is outside its validity window. The underlying error is available on the `details`
   *   property.
   *
   * @see https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-16.html#section-5
   */
  public override verifyClaims({ uri, requiredClaims = [], ...options }: VerifyStatusListCwtClaimsOptions): void {
    try {
      super.verifyClaims({
        ...options,
        expectedSubject: uri,
        requiredClaims: [RegisteredCwtClaimKey.Subject, RegisteredCwtClaimKey.IssuedAt, ...requiredClaims],
        keyLabels: StatusListCwtClaimKey,
      })
    } catch (error) {
      if (error instanceof CwtClaimVerificationError) {
        throw new SLException(`Status list token claim verification failed. ${error.message}`, error)
      }

      throw error
    }
  }

  /**
   * Verifies that the status at `idx` in this token's status list is `Valid`.
   *
   * @throws SLException if it is any other status.
   */
  public verifyStatus(idx: number): void {
    const status = this.statusList.getStatus(idx)

    if (status !== StatusType.Valid) {
      throw new SLException(`Status for id '${idx}' is not Valid (${StatusType.Valid}), but is instead '${status}'`)
    }
  }

  public setStatusList(statusList: StatusList | StatusListCbor) {
    this.claims.set(
      StatusListCwtClaimKey.StatusList,
      statusList instanceof StatusListCbor ? statusList : StatusListCbor.create({ statusList })
    )
  }
}
