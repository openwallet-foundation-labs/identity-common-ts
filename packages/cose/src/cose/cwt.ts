import { cborDecode } from '../cbor'
import type { CoseKey } from './key'
import { Mac0, type Mac0Context, type Mac0Options } from './mac0'
import { Sign1, type Sign1Context, type Sign1Options } from './sign1'

export type CwtOptions = Sign1Options | Mac0Options

export class Cwt {
  public constructor(private options: CwtOptions) {}

  public static create(options: CwtOptions) {
    return new Cwt(options)
  }

  public static fromToken(token: Uint8Array) {
    const decoded = cborDecode<Sign1 | Mac0>(token)
    return new Cwt(decoded)
  }

  public get asSign1() {
    return Sign1.create(this.options)
  }

  public get asMac0() {
    return Mac0.create(this.options)
  }

  public get payload() {
    return this.options.payload
  }

  public get protectedHeaders() {
    return this.options.protectedHeaders
  }

  public get unprotectedHeaders() {
    return this.options.unprotectedHeaders
  }

  public get signatureOrTag() {
    return 'signature' in this.options ? this.options.signature : 'tag' in this.options ? this.options.tag : undefined
  }

  public async verifySignature({ key }: { key: CoseKey }, ctx: Pick<Sign1Context, 'verify'>) {
    return await this.asSign1.verifySignature({ key }, ctx)
  }

  public async verifyAuthenticationCode({ key }: { key: CoseKey }, ctx: Pick<Mac0Context, 'verify'>) {
    return await this.asMac0.verifyAuthenticationCode({ key }, ctx)
  }
}
