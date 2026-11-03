import { z } from 'zod'
import { DcqlParseError } from '../dcql-error/e-dcql.js'
import { parseWithIssues, zIdString, zJsonRecord, zNonEmptyArray } from '../u-dcql.js'

export namespace DcqlPresentation {
  const zPresentationEntry = z.union([z.string(), zJsonRecord])

  export const zModel = z
    .union(
      [
        z.record(zIdString, zNonEmptyArray(zPresentationEntry)),
        z.record(
          zIdString,
          // We support presentation entry directly (not as array) to support older draft of DCQL
          zPresentationEntry
        ),
      ],
      {
        error:
          'Expected an object with credential query ids as keys, and for each a presentation or a non-empty array of presentations',
      }
    )
    .describe(
      'REQUIRED. This is a JSON-encoded object containing entries where the key is the id value used for a Credential Query in the DCQL query and the value is an array of one or more Presentations that match the respective Credential Query. When multiple is omitted, or set to false, the array MUST contain only one Presentation. There MUST NOT be any entry in the JSON-encoded object for optional Credential Queries when there are no matching Credentials for the respective Credential Query. Each Presentation is represented as a string or object, depending on the format as defined in Appendix B. The same rules as above apply for encoding the Presentations.'
    )

  export type Input = z.input<typeof zModel>
  export type Output = z.output<typeof zModel>

  /**
   * Parse a DCQL presentation, as an object or JSON encoded
   *
   * @throws {DcqlParseError} with the `issues` of the input when it is not a DCQL presentation
   */
  export const parse = (input: Input | string): Output => {
    let json: unknown = input
    if (typeof input === 'string') {
      try {
        json = JSON.parse(input)
      } catch (error) {
        throw new DcqlParseError({ message: 'Invalid JSON', cause: error })
      }
    }

    return parseWithIssues(zModel, json, 'DCQL presentation')
  }

  export const encode = (input: Output) => {
    return JSON.stringify(input)
  }
}
export type DcqlPresentation = DcqlPresentation.Output
