import type { CoseKey, Mac0Options } from '@owf/cose'
import { Mac0, type Mac0DecodedStructure, type Mac0EncodedStructure } from '@owf/cose'
import { stringToBytes } from '@owf/identity-common'
import type { MdocContext } from '../../context'
import { constantTimeEqual } from '../../utils/constantTimeEqual'
import { DeviceMacNotSupportedError } from '../errors'
import { SessionTranscript } from './session-transcript'

export type DeviceMacEncodedStructure = Mac0EncodedStructure
export type DeviceMacDecodedStructure = Mac0DecodedStructure
export type DeviceMacOptions = Mac0Options

type DeviceMacKeyAgreementOptions = {
  /**
   * The own key: the device key of the mdoc, or the ephemeral key of the mdoc reader.
   */
  key: CoseKey
  /**
   * The public key of the other party.
   */
  peerPublicKey: CoseKey
  sessionTranscript: SessionTranscript | Uint8Array
  detachedPayload?: Uint8Array
}

export class DeviceMac extends Mac0 {
  public async verify(options: DeviceMacKeyAgreementOptions, ctx: Pick<MdocContext, 'crypto'>) {
    if (constantTimeEqual(await this.calculateTag(options, ctx), this.tag)) return true

    const legacyToBeAuthenticated = this.legacyToBeAuthenticated({ detachedPayload: options.detachedPayload })
    return constantTimeEqual(await this.calculateTag(options, ctx, legacyToBeAuthenticated), this.tag)
  }

  /**
   * Sets the tag with the EMacKey of `key` and `peerPublicKey` (18013-5 9.1.3.5), computed by
   * `crypto.deviceMac` of the context.
   */
  public async authenticateWithKeyAgreement(options: DeviceMacKeyAgreementOptions, ctx: Pick<MdocContext, 'crypto'>) {
    this.structure.tag = await this.calculateTag(options, ctx)
    return this
  }

  public static create(options: DeviceMacOptions) {
    // biome-ignore lint/complexity/noThisInStatic: `super.create` keeps `this` bound to the subclass
    return super.create(options) as DeviceMac
  }

  private async calculateTag(
    options: DeviceMacKeyAgreementOptions,
    ctx: Pick<MdocContext, 'crypto'>,
    toBeAuthenticated = this.toBeAuthenticated({ detachedPayload: options.detachedPayload })
  ) {
    if (!ctx.crypto.deviceMac) {
      throw new DeviceMacNotSupportedError('The mdoc context does not provide crypto.deviceMac')
    }

    return await ctx.crypto.deviceMac({
      key: options.key,
      peerPublicKey: options.peerPublicKey,
      // 18013-5 9.1.3.5: the salt is SHA-256(SessionTranscriptBytes), so the transcript tagged with tag 24.
      salt: await ctx.crypto.digest({
        digestAlgorithm: 'SHA-256',
        bytes: SessionTranscript.from(options.sessionTranscript).encode({ asDataItem: true }),
      }),
      info: stringToBytes('EMacKey'),
      toBeAuthenticated,
    })
  }
}
