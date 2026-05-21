import type { Mac0Context } from '@owf/cose'
import {
  type CoseKey,
  Cwt,
  type ProtectedHeaderOptions,
  ProtectedHeaders,
  type Sign1Context,
  type SignatureAlgorithm,
  type UnprotectedHeaderOptions,
  UnprotectedHeaders,
} from '@owf/cose'
import { StatusList } from '../status-list'
import { type BitsPerStatus, MediaTypes } from '../types'
import { StatusListCbor } from './status-list-cbor'
import { type CreateStatusListCwtPayloadOptions, StatusListCwtPayload } from './status-list-cwt-payload'

export type StatusListCwtOptions = {
  payload: StatusListCwtPayload | CreateStatusListCwtPayloadOptions
  protectedHeaders?: ProtectedHeaders | ProtectedHeaderOptions['protectedHeaders']
  unprotectedHeaders?: UnprotectedHeaders | UnprotectedHeaderOptions['unprotectedHeaders']
}

export enum StatusListCwtHeaderKey {
  Typ = 16,
}

export class StatusListCwt {
  public payload: StatusListCwtPayload
  public protectedHeaders?: ProtectedHeaders
  public unprotectedHeaders?: UnprotectedHeaders

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

    if (this.protectedHeaders.headers.get(StatusListCwtHeaderKey.Typ) === undefined) {
      this.protectedHeaders.headers.set(StatusListCwtHeaderKey.Typ, MediaTypes.STATUS_LIST_CWT)
    }
  }

  public setStatusList(statusList: StatusList | StatusListCbor) {
    this.payload.setStatusList(statusList)
  }

  public updateStatusList(index: number, value: number) {
    this.payload.statusList.setStatus(index, value)
  }

  /**
   *
   * Create a minimal status list cwt. If you want to configure more options, use the constructor method
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

  public static fromToken(token: Uint8Array) {
    const cwt = Cwt.fromToken(token)
    const payload = StatusListCwtPayload.decode(cwt.payload)

    return new StatusListCwt({
      payload,
      protectedHeaders: cwt.protectedHeaders,
      unprotectedHeaders: cwt.unprotectedHeaders,
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

  public async authenticateAndEncode(options: { key: CoseKey }, ctx: Pick<Mac0Context, 'mac'>) {
    const cwt = new Cwt({
      protectedHeaders: this.protectedHeaders,
      unprotectedHeaders: this.unprotectedHeaders,
      payload: this.payload.encode(),
    })
    return (await cwt.asMac0.authenticate(options, ctx)).encode()
  }
}
