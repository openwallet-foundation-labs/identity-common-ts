import { CborStructure, TypedMap, typedMap } from '@owf/cose'
import { z } from 'zod'
import type { DataElementIdentifier } from './data-element-identifier'
import type { Namespace } from './namespace'

/**
 * A data element, by namespace and identifier (ISO/IEC TS 23220-4 7.2.1.3.2 `ElementReference`).
 */
export type ElementReference = [Namespace, DataElementIdentifier]

const elementReferenceSchema = z.tuple([z.string(), z.string()])

const alternativeDataElementsSetSchema = typedMap([
  ['requestedElement', elementReferenceSchema],
  ['alternativeElementSets', z.array(z.array(elementReferenceSchema).min(1)).min(1)],
] as const)

export type AlternativeDataElementsSetEncodedStructure = z.input<typeof alternativeDataElementsSetSchema>
export type AlternativeDataElementsSetDecodedStructure = z.output<typeof alternativeDataElementsSetSchema>

export type AlternativeDataElementsSetOptions = {
  requestedElement: ElementReference
  /**
   * The sets of elements that may be returned in place of the requested one, in the reader's order
   * of preference.
   */
  alternativeElementSets: Array<Array<ElementReference>>
}

/**
 * Elements that may be returned in place of a requested one (ISO/IEC TS 23220-4 7.2.1.3.2). Each set
 * answers the request on its own; the sets are in the reader's order of preference, the most
 * privacy-preserving first.
 */
export class AlternativeDataElementsSet extends CborStructure<
  AlternativeDataElementsSetEncodedStructure,
  AlternativeDataElementsSetDecodedStructure
> {
  public static override get encodingSchema() {
    return alternativeDataElementsSetSchema
  }

  public get requestedElement(): ElementReference {
    return this.structure.get('requestedElement')
  }

  public get alternativeElementSets(): Array<Array<ElementReference>> {
    return this.structure.get('alternativeElementSets')
  }

  public static create(options: AlternativeDataElementsSetOptions): AlternativeDataElementsSet {
    const map: AlternativeDataElementsSetDecodedStructure = new TypedMap([
      ['requestedElement', options.requestedElement],
      ['alternativeElementSets', options.alternativeElementSets],
    ])

    // biome-ignore lint/complexity/noThisInStatic: this.fromDecodedStructure is intentional for subclass support
    return this.fromDecodedStructure(map)
  }
}
