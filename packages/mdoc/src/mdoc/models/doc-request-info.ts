import { CborStructure, TypedMap, typedMap, zUint8Array } from '@owf/cose'
import { z } from 'zod'
import type { DataElementIdentifier } from './data-element-identifier'
import type { Namespace } from './namespace'

/**
 * A data element, by namespace and identifier (ISO/IEC TS 23220-4 7.2.1.3.2 `ElementReference`).
 */
export type ElementReference = [Namespace, DataElementIdentifier]

/**
 * Elements that may be returned in place of a requested one. Each set answers the request on its
 * own; the sets are in the reader's order of preference.
 */
export type AlternativeDataElementsSet = {
  requestedElement: ElementReference
  alternativeElementSets: Array<Array<ElementReference>>
}

const elementReferenceSchema = z.tuple([z.string(), z.string()])

// Validated as received and kept as a map, so that unknown (RFU) keys survive a re-encoding.
const alternativeDataElementsSetSchema = z.map(z.unknown(), z.unknown()).superRefine((set, ctx) => {
  if (!elementReferenceSchema.safeParse(set.get('requestedElement')).success) {
    ctx.addIssue({ code: 'custom', message: "Expected 'requestedElement' to be [namespace, dataElementIdentifier]" })
  }
  if (!z.array(z.array(elementReferenceSchema).min(1)).min(1).safeParse(set.get('alternativeElementSets')).success) {
    ctx.addIssue({
      code: 'custom',
      message: "Expected 'alternativeElementSets' to be a non-empty array of non-empty arrays of element references",
    })
  }
})

const docRequestInfoSchema = typedMap([
  ['alternativeDataElements', z.array(alternativeDataElementsSetSchema).min(1).exactOptional()],
  ['issuerIdentifiers', z.array(zUint8Array).min(1).exactOptional()],
  ['uniqueDocSetRequired', z.boolean().exactOptional()],
  ['maximumResponseSize', z.number().int().nonnegative().exactOptional()],
] as const)

export type DocRequestInfoEncodedStructure = z.input<typeof docRequestInfoSchema>
export type DocRequestInfoDecodedStructure = z.output<typeof docRequestInfoSchema>

export type DocRequestInfoOptions = {
  alternativeDataElements?: Array<AlternativeDataElementsSet>
  /**
   * Key identifiers of the authority key identifier of an acceptable issuer certificate. An mdoc
   * only satisfies the doc request when one of them matches a certificate in the x5chain of its
   * IssuerAuth.
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

  public get alternativeDataElements(): Array<AlternativeDataElementsSet> | undefined {
    return this.structure.get('alternativeDataElements')?.map((set) => ({
      requestedElement: set.get('requestedElement') as ElementReference,
      alternativeElementSets: set.get('alternativeElementSets') as Array<Array<ElementReference>>,
    }))
  }

  public get issuerIdentifiers() {
    return this.structure.get('issuerIdentifiers')
  }

  public get uniqueDocSetRequired() {
    return this.structure.get('uniqueDocSetRequired')
  }

  public get maximumResponseSize() {
    return this.structure.get('maximumResponseSize')
  }

  public static create(options: DocRequestInfoOptions): DocRequestInfo {
    const map: DocRequestInfoDecodedStructure = new TypedMap([])

    if (options.alternativeDataElements !== undefined) {
      map.set(
        'alternativeDataElements',
        options.alternativeDataElements.map(
          (set) =>
            new Map<unknown, unknown>([
              ['requestedElement', set.requestedElement],
              ['alternativeElementSets', set.alternativeElementSets],
            ])
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
