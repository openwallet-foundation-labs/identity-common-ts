import { TypedMap, typedMap } from '@owf/cose'
import { z } from 'zod'
import { OriginalBytesCborStructure } from '../original-bytes-cbor-structure'

/**
 * A use case of a device request: the doc requests, by index into `docRequests`, that answer it.
 * Exactly one document set has to be returned for the use case to be satisfied, every doc request
 * of that set included.
 */
export type UseCase = {
  /**
   * Whether the use case has to be satisfied for the device request to be.
   */
  mandatory: boolean
  /**
   * Why the reader asks, per purpose controller, as codes of a registry a profile defines.
   */
  purposeHints?: Map<string, number>
  documentSets: Array<Array<number>>
}

// Validated as received and kept as a map, so that unknown keys survive a re-encoding.
const useCaseSchema = z.map(z.unknown(), z.unknown()).superRefine((useCase, ctx) => {
  if (typeof useCase.get('mandatory') !== 'boolean') {
    ctx.addIssue({ code: 'custom', message: "Expected 'mandatory' to be a boolean" })
  }
  if (!z.array(z.array(z.number().int().nonnegative()).min(1)).min(1).safeParse(useCase.get('documentSets')).success) {
    ctx.addIssue({
      code: 'custom',
      message: "Expected 'documentSets' to be a non-empty array of non-empty arrays of doc request indexes",
    })
  }
  if (
    useCase.has('purposeHints') &&
    !z.map(z.string(), z.number().int()).safeParse(useCase.get('purposeHints')).success
  ) {
    ctx.addIssue({ code: 'custom', message: "Expected 'purposeHints' to map purpose controller ids to purpose codes" })
  }
})

const deviceRequestInfoSchema = typedMap([['useCases', z.array(useCaseSchema).min(1).exactOptional()]] as const)

export type DeviceRequestInfoEncodedStructure = z.input<typeof deviceRequestInfoSchema>
export type DeviceRequestInfoDecodedStructure = z.output<typeof deviceRequestInfoSchema>

export type DeviceRequestInfoOptions = {
  useCases?: Array<UseCase>
}

/**
 * Information on a device request as a whole, the `deviceRequestInfo` of a `DeviceRequest`
 * (ISO/IEC TS 23220-4 7.2.1.3.4, taken up by the second edition of ISO/IEC 18013-5): which doc
 * requests answer which use case.
 *
 * Embedded as `DeviceRequestInfoBytes` (tag 24), so the bytes are kept as received.
 */
export class DeviceRequestInfo extends OriginalBytesCborStructure<
  DeviceRequestInfoEncodedStructure,
  DeviceRequestInfoDecodedStructure
> {
  public static override get encodingSchema() {
    return deviceRequestInfoSchema
  }

  public get useCases(): Array<UseCase> | undefined {
    return this.structure.get('useCases')?.map((useCase) => {
      const purposeHints = useCase.get('purposeHints') as Map<string, number> | undefined
      return {
        mandatory: useCase.get('mandatory') as boolean,
        ...(purposeHints ? { purposeHints } : {}),
        documentSets: useCase.get('documentSets') as Array<Array<number>>,
      }
    })
  }

  public static create(options: DeviceRequestInfoOptions): DeviceRequestInfo {
    const map: DeviceRequestInfoDecodedStructure = new TypedMap([])

    if (options.useCases !== undefined) {
      map.set(
        'useCases',
        options.useCases.map((useCase) => {
          const entries: Array<[unknown, unknown]> = [['mandatory', useCase.mandatory]]
          if (useCase.purposeHints) entries.push(['purposeHints', useCase.purposeHints])
          entries.push(['documentSets', useCase.documentSets])
          return new Map(entries)
        })
      )
    }

    // biome-ignore lint/complexity/noThisInStatic: this.fromDecodedStructure is intentional for subclass support
    return this.fromDecodedStructure(map)
  }
}
