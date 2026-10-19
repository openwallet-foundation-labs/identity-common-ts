import { CborStructure, TypedMap, typedMap, zUint8Array } from '@owf/cose'
import { z } from 'zod'
import { structureArrayHooks } from '../../utils/structureArray'
import { zUnsignedInteger } from '../../utils/zodInteger'
import {
  AlternativeDataElementsSet,
  type AlternativeDataElementsSetEncodedStructure,
  type AlternativeDataElementsSetOptions,
} from './alternative-data-elements-set'

const docRequestInfoSchema = typedMap(
  [
    ['alternativeDataElements', z.array(z.instanceof(AlternativeDataElementsSet)).min(1).exactOptional()],
    ['issuerIdentifiers', z.array(zUint8Array).min(1).exactOptional()],
    ['uniqueDocSetRequired', z.boolean().exactOptional()],
    ['maximumResponseSize', zUnsignedInteger.exactOptional()],
  ] as const,
  structureArrayHooks('alternativeDataElements', (set) =>
    AlternativeDataElementsSet.fromEncodedStructure(set as AlternativeDataElementsSetEncodedStructure)
  )
)

export type DocRequestInfoEncodedStructure = z.input<typeof docRequestInfoSchema>
export type DocRequestInfoDecodedStructure = z.output<typeof docRequestInfoSchema>

export type DocRequestInfoOptions = {
  alternativeDataElements?: Array<AlternativeDataElementsSet | AlternativeDataElementsSetOptions>
  /**
   * Key identifiers of the authority key identifier of an acceptable issuer certificate. An mdoc
   * only satisfies the doc request when one of them is the authority key identifier of a certificate
   * in its chain: for a verifier the chain it validated, as the x5chain is unprotected, and for a
   * holder the x5chain of its IssuerAuth.
   */
  issuerIdentifiers?: Array<Uint8Array>
  uniqueDocSetRequired?: boolean
  /**
   * The largest unencrypted DeviceResponse, in bytes, the reader accepts.
   */
  maximumResponseSize?: number
}

/**
 * Additional information on a doc request, the `requestInfo` of an `ItemsRequest` (ISO/IEC TS
 * 23220-4 7.2.1.3.2, taken up by the second edition of ISO/IEC 18013-5).
 *
 * Keys this structure does not know are kept, so that an `ItemsRequest` re-encodes as received.
 */
export class DocRequestInfo extends CborStructure<DocRequestInfoEncodedStructure, DocRequestInfoDecodedStructure> {
  public static override get encodingSchema() {
    return docRequestInfoSchema
  }

  public get alternativeDataElements() {
    return this.structure.get('alternativeDataElements')
  }

  public get issuerIdentifiers() {
    return this.structure.get('issuerIdentifiers')
  }

  public get uniqueDocSetRequired() {
    return this.structure.get('uniqueDocSetRequired')
  }

  public get maximumResponseSize() {
    const maximumResponseSize = this.structure.get('maximumResponseSize')
    return maximumResponseSize === undefined ? undefined : Number(maximumResponseSize)
  }

  public static create(options: DocRequestInfoOptions): DocRequestInfo {
    const map: DocRequestInfoDecodedStructure = new TypedMap([])

    if (options.alternativeDataElements !== undefined) {
      map.set(
        'alternativeDataElements',
        options.alternativeDataElements.map((set) =>
          set instanceof AlternativeDataElementsSet ? set : AlternativeDataElementsSet.create(set)
        )
      )
    }
    if (options.issuerIdentifiers !== undefined) map.set('issuerIdentifiers', options.issuerIdentifiers)
    if (options.uniqueDocSetRequired !== undefined) map.set('uniqueDocSetRequired', options.uniqueDocSetRequired)
    if (options.maximumResponseSize !== undefined) map.set('maximumResponseSize', options.maximumResponseSize)

    // biome-ignore lint/complexity/noThisInStatic: this.fromDecodedStructure is intentional for subclass support
    return this.fromDecodedStructure(map)
  }
}
