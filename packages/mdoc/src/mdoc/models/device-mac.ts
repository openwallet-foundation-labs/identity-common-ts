import type { CoseKey, Mac0Options } from '@owf/cose'
import { Mac0, type Mac0DecodedStructure, type Mac0EncodedStructure } from '@owf/cose'
import { stringToBytes } from '@owf/identity-common'
import type { MdocContext } from '../../context'
import { SessionTranscript } from './session-transcript'

export type DeviceMacEncodedStructure = Mac0EncodedStructure
export type DeviceMacDecodedStructure = Mac0DecodedStructure
export type DeviceMacOptions = Mac0Options

export class DeviceMac extends Mac0 {
  public async verify(
    options: {
      publicKey: CoseKey
      privateKey: CoseKey
      info?: 'EMacKey' | 'SKReader' | 'SKDevice'
      sessionTranscript: SessionTranscript | Uint8Array
      detachedPayload?: Uint8Array
    },
    ctx: Pick<MdocContext, 'crypto' | 'cose'>
  ) {
    const key = await this.createDeviceMacKey(options, ctx)

    return ctx.cose.mac0.verify({
      toBeAuthenticated: this.toBeAuthenticated({
        detachedPayload: options.detachedPayload,
      }),
      key,
      tag: this.tag,
    })
  }

  public static create(options: DeviceMacOptions) {
    // biome-ignore lint/complexity/noThisInStatic: `super.create` keeps `this` bound to the subclass
    return super.create(options) as DeviceMac
  }

  public async createDeviceMacKey(
    options: {
      publicKey: CoseKey
      privateKey: CoseKey
      sessionTranscript: SessionTranscript | Uint8Array
      info?: 'EMacKey' | 'SKReader' | 'SKDevice'
    },
    ctx: Pick<MdocContext, 'crypto' | 'cose'>
  ) {
    return await ctx.crypto.hdkf({
      privateKey: options.privateKey.privateKey,
      publicKey: options.publicKey.publicKey,
      // 18013-5 9.1.3.5: the salt is SHA-256(SessionTranscriptBytes), so the transcript tagged with tag 24.
      salt: await ctx.crypto.digest({
        digestAlgorithm: 'SHA-256',
        bytes: SessionTranscript.from(options.sessionTranscript).encode({ asDataItem: true }),
      }),
      info: stringToBytes(options.info ?? 'EMacKey'),
    })
  }
}
