import { typedMap, zUint8Array } from '@owf/cose'
import { compareBytes } from '@owf/identity-common'
import { z } from 'zod'
import type { MdocContext } from '../../context'
import { OriginalBytesCborStructure } from '../original-bytes-cbor-structure'
import type { DataElementIdentifier } from './data-element-identifier'
import type { DataElementValue } from './data-element-value'
import type { IssuerAuth } from './issuer-auth'
import type { Namespace } from './namespace'

// IssuerSignedItem uses string keys per spec:
// IssuerSignedItem = {
//   "digestID" : uint,
//   "random" : bstr,
//   "elementIdentifier" : DataElementIdentifier,
//   "elementValue" : DataElementValue
// }
export const issuerSignedItemSchema = typedMap([
  ['digestID', z.number()],
  ['random', zUint8Array],
  ['elementIdentifier', z.string()],
  ['elementValue', z.unknown()],
])

export type IssuerSignedItemEncodedStructure = z.input<typeof issuerSignedItemSchema>
export type IssuerSignedItemDecodedStructure = z.output<typeof issuerSignedItemSchema>

// NOTE: Id vs ID above (user-facing API uses digestId, CBOR uses digestID)
export type IssuerSignedItemOptions = {
  digestId: number
  random: Uint8Array
  elementIdentifier: DataElementIdentifier
  elementValue: DataElementValue
}

/**
 * Decoded items keep the `IssuerSignedItemBytes` they were received as, as the digests in the MSO are
 * computed over them.
 */
export class IssuerSignedItem extends OriginalBytesCborStructure<
  IssuerSignedItemEncodedStructure,
  IssuerSignedItemDecodedStructure
> {
  public static override get encodingSchema() {
    return issuerSignedItemSchema
  }

  /**
   * @deprecated Use {@link originalBytes}.
   */
  public get originalPayloadBytes() {
    return this.originalBytes
  }

  public get random() {
    return this.structure.get('random')
  }

  public get elementIdentifier() {
    return this.structure.get('elementIdentifier')
  }

  public get elementValue() {
    return this.structure.get('elementValue')
  }

  public get digestId() {
    return this.structure.get('digestID')
  }

  public async isValid(namespace: Namespace, issuerAuth: IssuerAuth, ctx: Pick<MdocContext, 'crypto'>) {
    const digest = await ctx.crypto.digest({
      digestAlgorithm: issuerAuth.mobileSecurityObject.digestAlgorithm,
      bytes: this.encode({ asDataItem: true }),
    })

    const valueDigests = issuerAuth.mobileSecurityObject.valueDigests.valueDigests
    const digests = valueDigests.get(namespace)

    if (!digests) {
      return false
    }

    const expectedDigest = digests.get(this.digestId)

    return expectedDigest !== undefined && compareBytes(digest, expectedDigest)
  }

  public matchCertificate(issuerAuth: IssuerAuth, ctx: Pick<MdocContext, 'x509'>) {
    if (this.elementIdentifier === 'issuing_country') {
      return this.elementValue === issuerAuth.getIssuingCountry(ctx)
    }

    // 18013-5 7.2.1: the check "is only required if the stateOrProvinceName element is present in the DS
    // certificate".
    if (this.elementIdentifier === 'issuing_jurisdiction') {
      const stateOrProvince = issuerAuth.getIssuingStateOrProvince(ctx)
      return stateOrProvince === undefined || this.elementValue === stateOrProvince
    }

    return false
  }

  public static fromOptions(options: IssuerSignedItemOptions) {
    const map = new Map([
      ['digestID', options.digestId],
      ['random', options.random],
      ['elementIdentifier', options.elementIdentifier],
      ['elementValue', options.elementValue],
    ])
    // biome-ignore lint/complexity/noThisInStatic: this.fromEncodedStructure is intentional for subclass support
    return this.fromEncodedStructure(map)
  }
}
