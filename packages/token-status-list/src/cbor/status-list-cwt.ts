import {
  type AnyCwt,
  Cwt,
  CwtDetachedPayloadError,
  type CwtOptions,
  CwtPayloadDecodeError,
  type CwtStaticThis,
  type CwtStructures,
  ProtectedHeaders,
  RegisteredCwtHeaderClaimKey,
  TypedMap,
  type UnprotectedHeaderOptions,
  type UnprotectedHeaders,
} from '@owf/cose'
import { StatusList } from '../status-list'
import { SLException } from '../status-list-exception'
import { type BitsPerStatus, MediaTypes, StatusType } from '../types'
import { verifyStatusListClaims } from '../verify-status-list-claims'
import { StatusListCbor } from './status-list-cbor'
import { StatusListCwtProtectedHeaders } from './status-list-cwt-headers'
import { type CreateStatusListCwtPayloadOptions, StatusListCwtPayload } from './status-list-cwt-payload'

export type StatusListCwtOptions = Omit<
  CwtOptions<StatusListCwtPayload, StatusListCwtProtectedHeaders>,
  'payload' | 'protectedHeaders'
> & {
  payload: StatusListCwtPayload | CreateStatusListCwtPayloadOptions

  /**
   * The protected headers. `typ` (16) is set to the status list media type when absent, so only the
   * one value it is allowed to have has to be supplied.
   */
  protectedHeaders?: StatusListCwtProtectedHeaders | ProtectedHeaders | Map<number, unknown>

  unprotectedHeaders?: UnprotectedHeaders | UnprotectedHeaderOptions['unprotectedHeaders']
}

/**
 * Builds the protected headers of a status list CWT, defaulting `typ` (16) to the status list media
 * type. Validated against {@link StatusListCwtProtectedHeaders}, so a `typ` that is present but says
 * the token is something else is rejected here rather than silently overwritten.
 */
function statusListProtectedHeaders(
  protectedHeaders: StatusListCwtOptions['protectedHeaders']
): StatusListCwtProtectedHeaders {
  if (protectedHeaders instanceof StatusListCwtProtectedHeaders) return protectedHeaders

  const headers = new Map<number, unknown>(
    protectedHeaders instanceof ProtectedHeaders ? protectedHeaders.decodedStructure : protectedHeaders
  )
  if (headers.get(RegisteredCwtHeaderClaimKey.Typ) === undefined) {
    headers.set(RegisteredCwtHeaderClaimKey.Typ, MediaTypes.StatusListCwt)
  }

  return StatusListCwtProtectedHeaders.fromDecodedStructure(TypedMap.fromMap(headers))
}

/**
 * A status list token in CWT format: a CWT whose claims set carries a status list.
 *
 * @see https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-13.html#name-status-list-token-in-cwt-fo
 */
export class StatusListCwt extends Cwt<StatusListCwtPayload, StatusListCwtProtectedHeaders> {
  public constructor(options: StatusListCwtOptions) {
    super({
      ...options,
      protectedHeaders: statusListProtectedHeaders(options.protectedHeaders),
      payload:
        options.payload instanceof StatusListCwtPayload
          ? options.payload
          : StatusListCwtPayload.create(options.payload),
    })
  }

  public setStatusList(statusList: StatusList | StatusListCbor) {
    this.payload.setStatusList(statusList)
    this.markPayloadModified()
  }

  public updateStatusList(index: number, value: number) {
    this.payload.statusList.setStatus(index, value)
    this.markPayloadModified()
  }

  /**
   *
   * Create a minimal status list cwt. If you want to configure more options, like additional claims, use the constructor method
   *
   */
  public static createFromStatusListAndSubject(
    statusList:
      | StatusList
      | StatusListCbor
      | { statusList: number[]; bitsPerStatus: BitsPerStatus; aggregationUri?: string },
    subject: string
  ) {
    const cborStatusList =
      statusList instanceof StatusListCbor
        ? statusList
        : statusList instanceof StatusList
          ? StatusListCbor.create({ statusList })
          : StatusListCbor.create({
              bits: statusList.bitsPerStatus,
              list: statusList.statusList,
              aggregationUri: statusList.aggregationUri,
            })

    return new StatusListCwt({ payload: StatusListCwtPayload.create({ statusList: cborStatusList, subject }) })
  }

  /**
   * Decodes a status list CWT from a tagged COSE_Sign1 (tag 18) or COSE_Mac0 (tag 17) token.
   *
   * @throws SLException if the token is not a COSE token, has a detached payload, or the
   *   payload is not a valid status list CWT payload. The underlying error is available on
   *   the `details` property.
   */
  public static override fromToken<T extends AnyCwt>(this: CwtStaticThis<T>, token: Uint8Array): T {
    try {
      // NOTE: `super.fromToken`, not `Cwt.fromToken`: the base implementation constructs `this`, so
      // a further subclass of StatusListCwt is what comes back. The casts are because TypeScript
      // resolves `super.fromToken` against the base class, and cannot see that `T` is a status list
      // CWT and is therefore made of these structures.
      // biome-ignore lint/complexity/noThisInStatic: dispatching to the subclass is intentional
      return super.fromToken(token, {
        payload: StatusListCwtPayload,
        protectedHeaders: StatusListCwtProtectedHeaders,
      } as unknown as CwtStructures<T>) as T
    } catch (error) {
      if (error instanceof CwtDetachedPayloadError) {
        throw new SLException(
          'Cwt does not contain payload, detached payload is not supported for status list CWT',
          error
        )
      }

      if (error instanceof CwtPayloadDecodeError) {
        const cause = error.cause
        throw new SLException(
          `Unable to decode status list CWT payload: ${cause instanceof Error ? cause.message : String(cause)}`,
          error
        )
      }

      throw new SLException(
        `Unable to decode status list CWT: ${error instanceof Error ? error.message : String(error)}`,
        error
      )
    }
  }

  /**
   * Verify the token's claims and the status at `idx`. The claim checks are shared with the
   * JWT serialization through {@link verifyStatusListClaims}, so both stay in step.
   *
   * @todo add check for `ttl` claim
   */
  public verifyStatus({
    idx,
    uri,
    checkFreshness,
    now,
    skewSeconds,
    requireExpirationTime,
  }: {
    idx: number
    uri: string
    checkFreshness?: boolean
    now?: Date
    /** Clock tolerance applied to `exp` and `iat`, in seconds. Defaults to 30. */
    skewSeconds?: number
    /** Require `exp`, which is OPTIONAL by default. */
    requireExpirationTime?: boolean
  }) {
    verifyStatusListClaims({
      claims: {
        subject: this.payload.subject,
        issuedAt: this.payload.issuedAt,
        expirationTime: this.payload.expirationTime,
      },
      uri,
      now,
      skewSeconds,
      checkFreshness,
      requireExpirationTime,
    })

    if (this.payload.statusList.getStatus(idx) !== StatusType.Valid) {
      throw new SLException(
        `Status for id '${idx}' is not Valid (${StatusType.Valid}), but is instead '${this.payload.statusList.getStatus(idx)}'`
      )
    }
  }
}
