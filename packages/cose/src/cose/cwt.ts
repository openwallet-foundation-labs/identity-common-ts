import { Tag } from 'cbor-x'
import { cborDecode, describeCborValue } from '../cbor'
import { CosePayloadInvalidStructureError } from './error'
import type { CoseKey } from './key'
import { Mac0, type Mac0Context, type Mac0Options } from './mac0'
import { Sign1, type Sign1Context, type Sign1Options } from './sign1'

export type CwtOptions = Sign1Options | Mac0Options

/**
 * The CWT CBOR tag, defined in RFC 8392. It wraps the COSE structure rather than replacing it,
 * so a token tagged with it must be unwrapped before the COSE structure can be decoded.
 */
const CWT_TAG = 61

export class Cwt {
  public constructor(private options: CwtOptions) {}

  public static create(options: CwtOptions) {
    return new Cwt(options)
  }

  /**
   * Decodes a CWT from a tagged COSE_Sign1 (tag 18) or COSE_Mac0 (tag 17) token.
   *
   * @throws CborDecodeError if the token is not valid CBOR.
   * @throws CosePayloadInvalidStructureError if the token is valid CBOR but not a COSE_Sign1/COSE_Mac0.
   */
  public static fromToken(token: Uint8Array) {
    const decoded = cborDecode<unknown>(token)

    // The tag 18/17 cbor-x extensions turn a COSE token into a Sign1/Mac0 instance. Anything
    // else decoded fine as CBOR but isn't a COSE token, and would otherwise be accepted here
    // and only surface much later as a confusing 'payload is missing' error.
    if (!(decoded instanceof Sign1) && !(decoded instanceof Mac0)) {
      const cwtTagHint =
        decoded instanceof Tag && decoded.tag === CWT_TAG ? ' (the CWT tag, which must be unwrapped first)' : ''

      throw new CosePayloadInvalidStructureError(
        `Expected a tagged COSE_Sign1 (tag ${Sign1.tag}) or COSE_Mac0 (tag ${Mac0.tag}) structure, but decoded ${describeCborValue(decoded)}${cwtTagHint}. ` +
          'An untagged COSE structure is not supported; decode it with Sign1.decode or Mac0.decode instead.'
      )
    }

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
