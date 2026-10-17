import { CborStructure, TypedMap, typedMap } from '@owf/cose'
import { z } from 'zod'
import { zInteger, zUnsignedInteger } from '../../utils/zodInteger'

const useCaseSchema = typedMap([
  ['mandatory', z.boolean()],
  ['purposeHints', z.map(z.string(), zInteger).exactOptional()],
  ['documentSets', z.array(z.array(zUnsignedInteger).min(1)).min(1)],
] as const)

export type UseCaseEncodedStructure = z.input<typeof useCaseSchema>
export type UseCaseDecodedStructure = z.output<typeof useCaseSchema>

export type UseCaseOptions = {
  /**
   * Whether the use case has to be satisfied for the device request to be.
   */
  mandatory: boolean
  /**
   * Why the reader asks, per purpose controller, as codes of a registry a profile defines.
   */
  purposeHints?: Map<string, number>
  /**
   * The document sets that answer the use case, each a list of indexes into `docRequests`.
   */
  documentSets: Array<Array<number>>
}

/**
 * A use case of a device request (ISO/IEC TS 23220-4 7.2.1.3.4): the doc requests, by index into
 * `docRequests`, that answer it. Exactly one document set has to be returned for the use case to be
 * satisfied, every doc request of that set included.
 */
export class UseCase extends CborStructure<UseCaseEncodedStructure, UseCaseDecodedStructure> {
  public static override get encodingSchema() {
    return useCaseSchema
  }

  public get mandatory() {
    return this.structure.get('mandatory')
  }

  public get purposeHints(): Map<string, number> | undefined {
    const purposeHints = this.structure.get('purposeHints')
    return purposeHints && new Map(Array.from(purposeHints, ([controller, code]) => [controller, Number(code)]))
  }

  public get documentSets(): Array<Array<number>> {
    return this.structure.get('documentSets').map((set) => set.map(Number))
  }

  public static create(options: UseCaseOptions): UseCase {
    const map: UseCaseDecodedStructure = new TypedMap([['mandatory', options.mandatory]])
    if (options.purposeHints) map.set('purposeHints', options.purposeHints)
    map.set('documentSets', options.documentSets)

    // biome-ignore lint/complexity/noThisInStatic: this.fromDecodedStructure is intentional for subclass support
    return this.fromDecodedStructure(map)
  }
}
