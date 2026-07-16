import {
  type CoseKey,
  Cwt,
  type Mac0Context,
  type ProtectedHeaderOptions,
  ProtectedHeaders,
  RegisteredCwtClaimKey,
  type Sign1Context,
  type SignatureAlgorithm,
  type UnprotectedHeaderOptions,
  UnprotectedHeaders,
} from '@owf/cose'
import { StatusList } from '../status-list'
import { SLException } from '../status-list-exception'
import { type BitsPerStatus, MediaTypes, StatusType } from '../types'
import { StatusListCbor } from './status-list-cbor'
import { type CreateStatusListCwtPayloadOptions, StatusListCwtPayload } from './status-list-cwt-payload'

export type StatusListCwtOptions = {
  payload: StatusListCwtPayload | CreateStatusListCwtPayloadOptions
  protectedHeaders?: ProtectedHeaders | ProtectedHeaderOptions['protectedHeaders']
  unprotectedHeaders?: UnprotectedHeaders | UnprotectedHeaderOptions['unprotectedHeaders']
  signatureOrTag?: Uint8Array
  originalPayloadBytes?: Uint8Array
}

export enum StatusListCwtHeaderKey {
  Typ = 16,
}

export class StatusListCwt {
  public payload: StatusListCwtPayload
  public protectedHeaders?: ProtectedHeaders
  public unprotectedHeaders?: UnprotectedHeaders
  private signatureOrTag?: Uint8Array
  private originalPayloadBytes?: Uint8Array

  public constructor(options: StatusListCwtOptions) {
    this.payload =
      options.payload instanceof StatusListCwtPayload ? options.payload : StatusListCwtPayload.create(options.payload)
    this.protectedHeaders =
      options.protectedHeaders instanceof ProtectedHeaders
        ? options.protectedHeaders
        : ProtectedHeaders.create({ protectedHeaders: options.protectedHeaders })
    this.unprotectedHeaders =
      options.unprotectedHeaders instanceof UnprotectedHeaders
        ? options.unprotectedHeaders
        : UnprotectedHeaders.create({ unprotectedHeaders: options.unprotectedHeaders })

    this.signatureOrTag = options.signatureOrTag
    this.originalPayloadBytes = options.originalPayloadBytes

    if (this.protectedHeaders.headers.get(StatusListCwtHeaderKey.Typ) === undefined) {
      this.protectedHeaders.headers.set(StatusListCwtHeaderKey.Typ, MediaTypes.StatusListCwt)
    }
  }

  public setStatusList(statusList: StatusList | StatusListCbor) {
    this.payload.setStatusList(statusList)
    this.originalPayloadBytes = undefined
  }

  public updateStatusList(index: number, value: number) {
    this.payload.statusList.setStatus(index, value)
    this.originalPayloadBytes = undefined
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
  public static fromToken(token: Uint8Array) {
    let cwt: Cwt
    try {
      cwt = Cwt.fromToken(token)
    } catch (error) {
      throw new SLException(
        `Unable to decode status list CWT: ${error instanceof Error ? error.message : String(error)}`,
        error
      )
    }

    // A COSE token carries `null` for a detached payload, which we cannot resolve here.
    if (!cwt.payload) {
      throw new SLException('Cwt does not contain payload, detached payload is not supported for status list CWT')
    }

    let payload: StatusListCwtPayload
    try {
      payload = StatusListCwtPayload.decode(cwt.payload)
    } catch (error) {
      throw new SLException(
        `Unable to decode status list CWT payload: ${error instanceof Error ? error.message : String(error)}`,
        error
      )
    }

    return new StatusListCwt({
      payload,
      protectedHeaders: cwt.protectedHeaders,
      unprotectedHeaders: cwt.unprotectedHeaders,
      signatureOrTag: cwt.signatureOrTag,
      originalPayloadBytes: new Uint8Array(cwt.payload),
    })
  }

  public async signAndEncode(
    options: {
      signingKey: CoseKey
      algorithm?: SignatureAlgorithm
    },
    ctx: Pick<Sign1Context, 'sign'>
  ) {
    const cwt = new Cwt({
      protectedHeaders: this.protectedHeaders,
      unprotectedHeaders: this.unprotectedHeaders,
      payload: this.payload.encode(),
    })
    return (await cwt.asSign1.sign(options, ctx)).encode()
  }

  public async authenticateAndEncode(options: { key: CoseKey }, ctx: Pick<Mac0Context, 'authenticate'>) {
    const cwt = new Cwt({
      protectedHeaders: this.protectedHeaders,
      unprotectedHeaders: this.unprotectedHeaders,
      payload: this.payload.encode(),
    })
    return (await cwt.asMac0.authenticate(options, ctx)).encode()
  }

  /**
   * @todo add check for `ttl` claim
   */
  public verifyStatus({
    idx,
    uri,
    checkFreshness = true,
    now = new Date(),
  }: {
    idx: number
    uri: string
    checkFreshness?: boolean
    now?: Date
  }) {
    if (this.payload.expirationTime && this.payload.expirationTime < now) {
      throw new SLException(
        `The expiration claim (${RegisteredCwtClaimKey.ExpirationTime}) '${this.payload.expirationTime}' is in the past (compared to '${now}'), and therefore not valid`
      )
    }
    if (this.payload.subject !== uri) {
      throw new SLException(
        `The subject claim (${RegisteredCwtClaimKey.Subject}) '${this.payload.subject}' must be equal to the uri '${uri}'`
      )
    }
    if (checkFreshness && this.payload.issuedAt > now) {
      throw new SLException(
        `The issued at claim (${RegisteredCwtClaimKey.IssuedAt}) '${this.payload.issuedAt}' is in the future (compared to '${now}'), and therefore not valid`
      )
    }
    if (this.payload.statusList.getStatus(idx) !== StatusType.Valid) {
      throw new SLException(
        `Status for id '${idx}' is not Valid (${StatusType.Valid}), but is instead '${this.payload.statusList.getStatus(idx)}'`
      )
    }
  }

  public async verifySignature({ key }: { key: CoseKey }, ctx: Pick<Sign1Context, 'verify'>) {
    const cwt = new Cwt({
      protectedHeaders: this.protectedHeaders,
      unprotectedHeaders: this.unprotectedHeaders,
      payload: this.originalPayloadBytes ?? this.payload.encode(),
      signature: this.signatureOrTag,
    })

    return await cwt.verifySignature({ key }, ctx)
  }

  public async verifyAuthenticationCode({ key }: { key: CoseKey }, ctx: Pick<Mac0Context, 'verify'>) {
    const cwt = new Cwt({
      protectedHeaders: this.protectedHeaders,
      unprotectedHeaders: this.unprotectedHeaders,
      payload: this.originalPayloadBytes ?? this.payload.encode(),
      tag: this.signatureOrTag,
    })

    return await cwt.verifyAuthenticationCode({ key }, ctx)
  }
}
