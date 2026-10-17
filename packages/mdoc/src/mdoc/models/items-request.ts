import { TypedMap, typedMap } from '@owf/cose'
import { z } from 'zod'
import { describeAgeOverLimitViolations, findAgeOverRequestLimitViolations } from '../../utils/ageOver'
import { AgeOverLimitExceededError } from '../errors'
import { OriginalBytesCborStructure } from '../original-bytes-cbor-structure'
import type { DataElementIdentifier } from './data-element-identifier'
import { DocRequestInfo, type DocRequestInfoOptions } from './doc-request-info'
import type { DocType } from './doctype'
import type { IntentToRetain } from './intent-to-retain'
import type { Namespace } from './namespace'

const namespacesSchema = z.map(z.string(), z.map(z.string(), z.boolean()))

// Zod schema for ItemsRequest
const itemsRequestSchema = typedMap(
  [
    ['docType', z.string()],
    ['nameSpaces', namespacesSchema],
    ['requestInfo', z.instanceof(DocRequestInfo).exactOptional()],
  ] as const,
  {
    decode: (input, originalDecode) => {
      const map = originalDecode(input)
      // Anything but a map is left for the schema to reject.
      const requestInfo = input.get('requestInfo')
      if (requestInfo instanceof Map) map.set('requestInfo', DocRequestInfo.fromEncodedStructure(requestInfo))
      return map
    },
    encode: (output, originalEncode) => {
      const map = originalEncode(output)
      const requestInfo = output.get('requestInfo')
      if (requestInfo) map.set('requestInfo', requestInfo.encodedStructure)
      return map
    },
  }
)

export type ItemsRequestEncodedStructure = z.input<typeof itemsRequestSchema>
export type ItemsRequestDecodedStructure = z.output<typeof itemsRequestSchema>

type NamespacesStructure = z.infer<typeof namespacesSchema>

export type ItemsRequestOptions = {
  docType: DocType
  namespaces:
    | NamespacesStructure
    // We allow record when creating for easier usage
    | Record<Namespace, Record<DataElementIdentifier, IntentToRetain>>
  requestInfo?: DocRequestInfo | DocRequestInfoOptions
}

export class ItemsRequest extends OriginalBytesCborStructure<
  ItemsRequestEncodedStructure,
  ItemsRequestDecodedStructure
> {
  public static override get encodingSchema() {
    return itemsRequestSchema
  }

  public get docType() {
    return this.structure.get('docType')
  }

  public get namespaces() {
    return this.structure.get('nameSpaces')
  }

  /**
   * The `requestInfo` of ISO/IEC TS 23220-4 7.2.1.3.2.
   */
  public get requestInfo() {
    return this.structure.get('requestInfo')
  }

  /**
   * Throws an `AgeOverLimitExceededError` when more than two `age_over_NN` elements are requested in
   * a namespace (18013-5 7.2.5). A decoded items request is not checked, so that the mdoc can report
   * such a request instead.
   */
  public static create(options: ItemsRequestOptions): ItemsRequest {
    const namespaces =
      options.namespaces instanceof Map
        ? options.namespaces
        : new Map(Object.entries(options.namespaces).map(([ns, inner]) => [ns, new Map(Object.entries(inner))]))

    const violations = findAgeOverRequestLimitViolations(namespaces)
    if (violations.length > 0) {
      throw new AgeOverLimitExceededError(
        `Items request for docType '${options.docType}' requests ${describeAgeOverLimitViolations(violations)}, but at most two age_over_NN elements may be requested per namespace`
      )
    }

    const structure: ItemsRequestDecodedStructure = new TypedMap([
      ['docType', options.docType],
      ['nameSpaces', namespaces],
    ])
    if (options.requestInfo) {
      structure.set(
        'requestInfo',
        options.requestInfo instanceof DocRequestInfo ? options.requestInfo : DocRequestInfo.create(options.requestInfo)
      )
    }

    // biome-ignore lint/complexity/noThisInStatic: this.fromDecodedStructure is intentional for subclass support
    return this.fromDecodedStructure(structure)
  }
}
