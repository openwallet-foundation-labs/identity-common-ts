import { z } from 'zod'
import { isObject, type NonEmptyArray, zIdString, zJsonTypes, zNonEmptyArray } from '../u-dcql.js'

/**
 * A Credential Set Query is an object representing
 * a request for one or more credentials to satisfy a particular use case with the Verifier.
 */
export namespace CredentialSetQuery {
  export const zModel = z.object({
    options: zNonEmptyArray(z.array(zIdString)).describe(
      'REQUIRED. A non-empty array, where each value in the array is a list of Credential Query identifiers representing one set of Credentials that satisfies the use case.'
    ),
    required: z
      .boolean()
      .default(true)
      .describe(
        `OPTIONAL. Boolean which indicates whether this set of Credentials is required to satisfy the particular use case at the Verifier. If omitted, the default value is 'true'.`
      ),
    purpose: zJsonTypes<string | number | Record<string, unknown>>(
      'a string, a number or an object',
      (value) => typeof value === 'string' || typeof value === 'number' || isObject(value)
    )
      .optional()
      .describe('OPTIONAL. A string, number or object specifying the purpose of the query.'),
  })

  export type Input = z.input<typeof zModel>
  export type Output = z.output<typeof zModel>
}
export type CredentialSetQuery = CredentialSetQuery.Output

/**
 * OpenID4VP 1.0 Section 6.4.2: without `credential_sets` every credential query is requested, otherwise an option of
 * each required credential set. `isMatched` tells whether a credential query is matched.
 */
export function matchCredentialSets(
  dcqlQuery: { credentials: { id: string }[]; credential_sets?: CredentialSetQuery[] },
  isMatched: (credentialQueryId: string) => boolean
) {
  const credentialSets = dcqlQuery.credential_sets?.map((set) => {
    const matchingOptions = set.options.filter((option) => option.every(isMatched))

    return {
      ...set,
      matching_options: matchingOptions.length > 0 ? (matchingOptions as NonEmptyArray<string[]>) : undefined,
    }
  }) as NonEmptyArray<CredentialSetQuery & { matching_options: NonEmptyArray<string[]> | undefined }> | undefined

  const isSatisfied = credentialSets
    ? credentialSets.every((set) => !set.required || set.matching_options)
    : dcqlQuery.credentials.every(({ id }) => isMatched(id))

  return { credentialSets, isSatisfied }
}
