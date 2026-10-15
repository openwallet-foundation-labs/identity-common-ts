import { typedMap } from '@owf/cose'
import { z } from 'zod'
import { describeAgeOverLimitViolations, findAgeOverRequestLimitViolations } from '../../utils/ageOver'
import { AgeOverLimitExceededError } from '../errors'
import { OriginalBytesCborStructure } from '../original-bytes-cbor-structure'
import type { DataElementIdentifier } from './data-element-identifier'
import { DocRequestInfo } from './doc-request-info'
import type { DocType } from './doctype'
import type { IntentToRetain } from './intent-to-retain'
import type { Namespace } from './namespace'

const namespacesSchema = z.map(z.string(), z.map(z.string(), z.boolean()))

// Zod schema for ItemsRequest. A `requestInfo` that does not match the CDDL of ISO/IEC TS 23220-4
// is kept as received rather than failing the request: the mdoc app ignores what it cannot
// interpret (7.2.1.3.2), and the items request is signed as received.
const itemsRequestSchema = typedMap(
  [
    ['docType', z.string()],
    ['nameSpaces', namespacesSchema],
    ['requestInfo', z.union([z.instanceof(DocRequestInfo), z.map(z.unknown(), z.unknown())]).exactOptional()],
  ] as const,
  {
    decode: (input, originalDecode) => {
      const map = originalDecode(input)
      const requestInfo = input.get('requestInfo')
      if (requestInfo instanceof Map) {
        try {
          map.set('requestInfo', DocRequestInfo.fromEncodedStructure(requestInfo))
        } catch {
          // Not a DocRequestInfo this version understands: left as is.
        }
      }
      return map
    },
    encode: (output, originalEncode) => {
      const map = originalEncode(output)
      const requestInfo = output.get('requestInfo')
      if (requestInfo instanceof DocRequestInfo) map.set('requestInfo', requestInfo.encodedStructure)
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
  requestInfo?: DocRequestInfo
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
   * The `requestInfo` of ISO/IEC TS 23220-4 7.2.1.3.2, when present and readable. One that does
   * not match its CDDL is not returned, and stays in the encoded items request as received.
   */
  public get requestInfo(): DocRequestInfo | undefined {
    const requestInfo = this.structure.get('requestInfo')
    return requestInfo instanceof DocRequestInfo ? requestInfo : undefined
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

    const structure = new Map<unknown, unknown>([
      ['docType', options.docType],
      ['nameSpaces', namespaces],
    ])
    if (options.requestInfo) structure.set('requestInfo', options.requestInfo.encodedStructure)

    // biome-ignore lint/complexity/noThisInStatic: this.fromEncodedStructure is intentional for subclass support
    return this.fromEncodedStructure(structure)
  }
}
