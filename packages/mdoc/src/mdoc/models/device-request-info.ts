import { TypedMap, typedMap } from '@owf/cose'
import { z } from 'zod'
import { structureArrayHooks } from '../../utils/structureArray'
import { OriginalBytesCborStructure } from '../original-bytes-cbor-structure'
import { UseCase, type UseCaseEncodedStructure, type UseCaseOptions } from './use-case'

const deviceRequestInfoSchema = typedMap(
  [['useCases', z.array(z.instanceof(UseCase)).min(1).exactOptional()]] as const,
  structureArrayHooks('useCases', (useCase) => UseCase.fromEncodedStructure(useCase as UseCaseEncodedStructure))
)

export type DeviceRequestInfoEncodedStructure = z.input<typeof deviceRequestInfoSchema>
export type DeviceRequestInfoDecodedStructure = z.output<typeof deviceRequestInfoSchema>

export type DeviceRequestInfoOptions = {
  useCases?: Array<UseCase | UseCaseOptions>
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

  public get useCases() {
    return this.structure.get('useCases')
  }

  public static create(options: DeviceRequestInfoOptions): DeviceRequestInfo {
    const map: DeviceRequestInfoDecodedStructure = new TypedMap([])

    if (options.useCases !== undefined) {
      map.set(
        'useCases',
        options.useCases.map((useCase) => (useCase instanceof UseCase ? useCase : UseCase.create(useCase)))
      )
    }

    // biome-ignore lint/complexity/noThisInStatic: this.fromDecodedStructure is intentional for subclass support
    return this.fromDecodedStructure(map)
  }
}
