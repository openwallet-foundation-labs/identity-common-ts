import { z } from 'zod'
import { isObject, zIdString, zJsonTypes, zNonEmptyArray } from '../u-dcql.js'

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
