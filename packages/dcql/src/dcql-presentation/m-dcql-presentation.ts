import type { SchemaValidationCode, ValidationIssueInput } from '@owf/identity-common'
import { z } from 'zod'
import { DcqlParseError } from '../dcql-error/e-dcql.js'
import type { DcqlCredentialQuery } from '../dcql-query/m-dcql-credential-query.js'
import { matchCredentialSets } from '../dcql-query/m-dcql-credential-set-query.js'
import type { DcqlQuery } from '../dcql-query/m-dcql-query.js'
import {
  addDcqlIssue,
  DCQL_VALIDATION_CODES,
  type DcqlValidationCode,
  type DcqlValidationContexts,
  hasOwn,
  parseWithIssues,
  zIdString,
  zJsonRecord,
  zNonEmptyArray,
} from '../u-dcql.js'

type DcqlViolation = ValidationIssueInput<DcqlValidationCode | SchemaValidationCode, DcqlValidationContexts>

// OpenID4VP 1.0 Section 8.1: a presentation is a string or an object, depending on its format (Appendix B)
const presentationJsonTypes: Record<DcqlCredentialQuery['format'], 'string' | 'object'> = {
  // Appendix B.2.5: a base64url-encoded DeviceResponse
  mso_mdoc: 'string',
  // Appendix B.3.6: an SD-JWT, with a Key Binding JWT when holder binding is required
  'dc+sd-jwt': 'string',
  // An SD-JWT, the identifier of SD-JWT VC in earlier drafts and of W3C VCDM 2.0 secured with SD-JWT
  'vc+sd-jwt': 'string',
  // Appendix B.1.3.1: a Verifiable Presentation as a JWT
  jwt_vc_json: 'string',
  // Appendix B.1.3.2: a Verifiable Presentation with a Data Integrity proof
  ldp_vc: 'object',
}

/**
 * The violations of a vp_token that can be found before its presentations are verified: a key that is not the id of a
 * credential query, more than one presentation for a credential query without `multiple`, a presentation that is not the
 * JSON type of its format (OpenID4VP 1.0 Section 8.1), and a required credential query without a presentation
 * (Section 6.4.2).
 */
function findVpTokenViolations(vpToken: Record<string, unknown>, dcqlQuery: DcqlQuery) {
  const violations: DcqlViolation[] = []

  for (const [credentialQueryId, presentations] of Object.entries(vpToken)) {
    const credentialQuery = dcqlQuery.credentials.find(({ id }) => id === credentialQueryId)
    if (!credentialQuery) {
      violations.push({
        code: DCQL_VALIDATION_CODES.UNKNOWN_CREDENTIAL_QUERY_ID,
        path: [credentialQueryId],
        message: `The presentation refers to the credential query id '${credentialQueryId}', which is not in credentials`,
      })
      continue
    }

    const entries = Array.isArray(presentations) ? presentations : [presentations]
    if (!credentialQuery.multiple && entries.length > 1) {
      violations.push({
        code: DCQL_VALIDATION_CODES.MULTIPLE_PRESENTATIONS_NOT_ALLOWED,
        path: [credentialQueryId],
        message: `Credential query '${credentialQueryId}' has ${entries.length} presentations, but allows only one without 'multiple'`,
      })
    }

    const expected = presentationJsonTypes[credentialQuery.format]
    // The first one is enough to reject the vp_token, and keeps the error from growing with it
    const index = entries.findIndex((entry) => (typeof entry === 'string' ? 'string' : 'object') !== expected)
    if (index !== -1) {
      violations.push({
        code: 'invalid_type',
        path: Array.isArray(presentations) ? [credentialQueryId, index] : [credentialQueryId],
        message: `Expected a presentation of format '${credentialQuery.format}' to be ${expected === 'string' ? 'a string' : 'an object'}`,
        context: { expected },
      })
    }
  }

  const { credentialSets } = matchCredentialSets(dcqlQuery, (credentialQueryId) => hasOwn(vpToken, credentialQueryId))
  if (credentialSets) {
    credentialSets.forEach((credentialSet, index) => {
      if (!credentialSet.required || credentialSet.matching_options) return
      violations.push({
        code: DCQL_VALIDATION_CODES.UNSATISFIED_CREDENTIAL_SET,
        path: [],
        message: `Credential set ${index} is required, but none of its options has a presentation for each of its credential queries`,
      })
    })
  } else {
    for (const { id } of dcqlQuery.credentials) {
      if (hasOwn(vpToken, id)) continue
      violations.push({
        code: 'missing_value',
        path: [id],
        message: `Expected a presentation for the credential query '${id}'`,
        context: { expected: 'array' },
      })
    }
  }

  return violations
}

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
   * With the `dcqlQuery` of the request, it also checks the rules of OpenID4VP 1.0 that do not need the presentations
   * to be verified, so a verifier can check them first: each key is the id of a credential query, a credential query
   * without `multiple` has one presentation, each presentation is the JSON type of its format (Section 8.1), and each
   * required credential query has a presentation (Section 6.4.2).
   *
   * @throws {DcqlParseError} with the `issues` of the input when it is not a DCQL presentation
   */
  export const parse = (input: Input | string, ctx?: { dcqlQuery: DcqlQuery }): Output => {
    let json: unknown = input
    if (typeof input === 'string') {
      try {
        json = JSON.parse(input)
      } catch (error) {
        throw new DcqlParseError({ message: 'Invalid JSON', cause: error })
      }
    }

    const schema = ctx
      ? zModel.superRefine((presentation, refinementCtx) => {
          for (const violation of findVpTokenViolations(presentation, ctx.dcqlQuery)) {
            addDcqlIssue(refinementCtx, violation)
          }
        })
      : zModel
    return parseWithIssues(schema, json, 'DCQL presentation')
  }

  export const encode = (input: Output) => {
    return JSON.stringify(input)
  }
}
export type DcqlPresentation = DcqlPresentation.Output
