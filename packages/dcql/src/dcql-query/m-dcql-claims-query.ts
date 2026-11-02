import { z } from 'zod'
import { isObject, zEither, zIdString, zJsonTypes, zNonEmptyArray } from '../u-dcql.js'

const idDescription =
  'A string identifying the particular claim. The value MUST be a non-empty string consisting of alphanumeric, underscore (_) or hyphen (-) characters. Within the particular claims array, the same id MUST NOT be present more than once.'
const valuesDescription =
  'An array of strings, integers or boolean values that specifies the expected values of the claim. If the values property is present, the Wallet SHOULD return the claim only if the type and value of the claim both match for at least one of the elements in the array.'
const namespaceDescription =
  'A string that specifies the namespace of the data element within the mdoc, e.g., org.iso.18013.5.1.'
const claimNameDescription =
  'A string that specifies the data element identifier of the data element within the provided namespace in the mdoc, e.g., first_name.'

/**
 * Specifies claims within a requested Credential.
 */
export namespace DcqlClaimsQuery {
  export const zValue = zJsonTypes<string | number | boolean>(
    'a string, an integer or a boolean',
    (value) => typeof value === 'string' || Number.isInteger(value) || typeof value === 'boolean'
  )

  export const zPath = zJsonTypes<string | number | null>(
    'a string, a non-negative integer or null',
    (value) => typeof value === 'string' || value === null || (Number.isSafeInteger(value) && (value as number) >= 0)
  )

  export const zW3cSdJwtVc = z.object({
    id: zIdString.optional().describe(idDescription),
    path: zNonEmptyArray(zPath).describe(
      'A non-empty array representing a claims path pointer that specifies the path to a claim within the Verifiable Credential.'
    ),
    values: z.array(zValue).optional().describe(valuesDescription),
  })
  export type W3cAndSdJwtVc = z.output<typeof zW3cSdJwtVc>

  const zMdocBase = z.object({
    id: zIdString.optional().describe(idDescription),
    values: z.array(zValue).optional().describe(valuesDescription),
  })

  // Syntax up until Draft 23 of OID4VP. Keeping due to Draft 23 having
  // reach ID-3 status and thus being targeted by several implementations
  export const zMdocNamespace = zMdocBase.extend({
    namespace: z.string().describe(namespaceDescription),
    claim_name: z.string().describe(claimNameDescription),
  })

  // Syntax starting from Draft 24 of OID4VP
  export const zMdocPath = zMdocBase.extend({
    intent_to_retain: z
      .boolean()
      .optional()
      .describe(
        'A boolean that is equivalent to `IntentToRetain` variable defined in Section 8.3.2.1.2.1 of [@ISO.18013-5].'
      ),

    path: zJsonTypes<[string, string]>(
      'an array of two strings, a namespace and a data element identifier',
      (path) => Array.isArray(path) && path.length === 2 && path.every((element) => typeof element === 'string')
    ).describe(
      'An array defining a claims path pointer into an mdoc. It must contain two elements of type string. The first element refers to a namespace and the second element refers to a data element identifier.'
    ),
  })
  export const zMdoc = zEither((value) => isObject(value) && 'namespace' in value, zMdocNamespace, zMdocPath)
  export type MdocNamespace = z.output<typeof zMdocNamespace>
  export type MdocPath = z.output<typeof zMdocPath>
  export type Mdoc = z.output<typeof zMdoc>

  export const zModel = z.union([zMdoc, zW3cSdJwtVc])
  export type Input = z.input<typeof zModel>
  export type Out = z.output<typeof zModel>

  export type ClaimValue = z.output<typeof zValue>
}
export type DcqlClaimsQuery = DcqlClaimsQuery.Out
