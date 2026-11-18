/**
 * Over-asking check
 *
 * Compares the DCQL query of an OpenID4VP request with the credentials and claims a
 * Wallet-Relying Party registered, as listed in the `credentials` of its registration certificate (ETSI TS
 * 119 475 Table 9), which follow the shape of a DCQL Credential Query.
 */

import {
  parseWithSchema,
  type SchemaValidationCode,
  toValidationResult,
  type ValidationIssueOf,
  ValidationIssues,
  type ValidationResult,
} from '@owf/identity-common'
import { DCQL_VALIDATION_CODES, DcqlQuery, type DcqlValidationCode, type DcqlValidationContexts } from 'dcql'

/** Codes of the issues of {@link checkOverAsking} */
export const OVER_ASKING_CODES = {
  /** A claims query has the `namespace` and `claim_name` form of earlier drafts instead of a `path` */
  INVALID_QUERY: 'invalid_query',
  /** No registered credential has the requested format and covers the requested `meta` */
  CREDENTIAL_NOT_REGISTERED: 'credential_not_registered',
  /** No registered claim covers the requested claim path */
  CLAIM_NOT_REGISTERED: 'claim_not_registered',
  /** The registered claim only allows certain values, and the request asks for others or for any */
  CLAIM_VALUES_NOT_REGISTERED: 'claim_values_not_registered',
  /** The matching registered credential lists no claims, so the requested ones cannot be confirmed */
  CLAIMS_NOT_LISTED: 'claims_not_listed',
} as const

export type OverAskingCode = (typeof OVER_ASKING_CODES)[keyof typeof OVER_ASKING_CODES]

/**
 * An issue of {@link checkOverAsking}, with a path into the DCQL query, e.g. `['credentials', 0, 'claims', 2]`.
 * A query the `dcql` library rejects has its issues, with a code of `DCQL_VALIDATION_CODES` or a schema code.
 */
export type OverAskingIssue = ValidationIssueOf<
  OverAskingCode | DcqlValidationCode | SchemaValidationCode,
  DcqlValidationContexts
>

/** `valid` when the request asks for nothing beyond the registration */
export type OverAskingResult = ValidationResult<OverAskingIssue>

type ClaimPath = (string | number | null)[]
type ClaimValue = string | number | boolean

/** A registered credential, from the `credentials` of a registration certificate. Either spelling of the claims array is read. */
export interface RegisteredCredential {
  format: string
  meta: Record<string, unknown>
  claim?: { path: ClaimPath; values?: ClaimValue[] }[]
  claims?: { path: ClaimPath; values?: ClaimValue[] }[]
}

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value)

function deepEqual(a: unknown, b: unknown): boolean {
  if (Array.isArray(a) && Array.isArray(b)) {
    return a.length === b.length && a.every((item, index) => deepEqual(item, b[index]))
  }
  if (isRecord(a) && isRecord(b)) {
    const keys = Object.keys(a)
    return keys.length === Object.keys(b).length && keys.every((key) => key in b && deepEqual(a[key], b[key]))
  }
  return a === b
}

/**
 * Whether the requested `meta` value stays within the registered one: every registered
 * property is restricted at least as much by the request, and a requested array, such as
 * `vct_values`, only holds registered elements. A property only the request has narrows it
 * further, so it is fine.
 */
function metaCovered(requested: unknown, registered: unknown): boolean {
  if (isRecord(registered)) {
    return (
      isRecord(requested) &&
      Object.keys(registered).every((key) => key in requested && metaCovered(requested[key], registered[key]))
    )
  }
  if (Array.isArray(registered)) {
    return (
      Array.isArray(requested) && requested.every((element) => registered.some((other) => deepEqual(element, other)))
    )
  }
  return deepEqual(requested, registered)
}

/**
 * Whether a registered claims path pointer covers a requested one: it is equal or a prefix,
 * as registering an object covers its members, and `null` registers every array element.
 */
function pathCovered(requested: ClaimPath, registered: ClaimPath): boolean {
  return (
    registered.length <= requested.length && registered.every((key, index) => key === null || key === requested[index])
  )
}

const describeMeta = (meta: unknown) => (isRecord(meta) && Object.keys(meta).length > 0 ? JSON.stringify(meta) : '{}')

/**
 * Check that an OpenID4VP request asks for no credential or claim beyond what the
 * Wallet-Relying Party registered in its registration certificate.
 *
 * A requested credential needs a registered one of the same format whose `meta` the
 * request stays within. Each requested claim then needs a registered claim of such a
 * credential with an equal or a parent path; if that claim lists `values`, the request
 * has to ask for some of these values only. A credential query without `claims` asks for
 * no selectively disclosable claims, so only the credential is checked.
 *
 * A registered credential without claims is reported as a warning for each credential
 * query with claims, as the registration does not say which claims are allowed. A query
 * that the `dcql` library rejects only gets its issues, e.g. `duplicate_credential_query_id`.
 *
 * @param query The DCQL query of the request, e.g. its `dcql_query` parameter, which is parsed and validated with the `dcql` library
 * @param registeredCredentials The `credentials` of the registration certificate payload
 */
export function checkOverAsking(
  query: unknown,
  registeredCredentials: readonly RegisteredCredential[] = []
): OverAskingResult {
  const parsed = parseWithSchema<typeof DcqlQuery.zModel, DcqlValidationCode, DcqlValidationContexts>(
    DcqlQuery.zModel,
    query,
    { codes: DCQL_VALIDATION_CODES }
  )
  if (!parsed.success) return toValidationResult<OverAskingIssue>(parsed.issues)

  const issues = new ValidationIssues<OverAskingCode>()

  parsed.data.credentials.forEach((credential, credentialIndex) => {
    const credentialPath = ['credentials', credentialIndex]
    const label = `Credential query ${credential.id}`
    const sameFormat = registeredCredentials.filter((registered) => registered.format === credential.format)
    const matching = sameFormat.filter((registered) => metaCovered(credential.meta ?? {}, registered.meta))
    if (matching.length === 0) {
      issues.add({
        code: OVER_ASKING_CODES.CREDENTIAL_NOT_REGISTERED,
        path: sameFormat.length === 0 ? [...credentialPath, 'format'] : [...credentialPath, 'meta'],
        message:
          sameFormat.length === 0
            ? `${label} asks for a ${credential.format} credential, and none of this format is registered`
            : `${label} asks for a ${credential.format} credential with meta ${describeMeta(credential.meta)}, which no registered ${credential.format} credential covers`,
      })
      return
    }

    if (!credential.claims) return

    const registeredClaims = matching.flatMap((registered) => registered.claim ?? registered.claims ?? [])
    if (matching.some((registered) => !(registered.claim ?? registered.claims))) {
      issues.add({
        severity: 'warning',
        code: OVER_ASKING_CODES.CLAIMS_NOT_LISTED,
        path: [...credentialPath, 'claims'],
        message: `The registered ${credential.format} credential lists no claims, so the claims of ${label} cannot be confirmed`,
      })
      return
    }

    credential.claims.forEach((claim, claimIndex) => {
      const queryPath = [...credentialPath, 'claims', claimIndex]
      // OpenID4VP 1.0 section 6.3 has only `path`; the DCQL library still parses the mdoc namespace form of earlier drafts
      if (!('path' in claim)) {
        issues.add({
          code: OVER_ASKING_CODES.INVALID_QUERY,
          path: queryPath,
          message: 'A claims query must have a path, the namespace and claim_name form is not supported',
        })
        return
      }
      const { path } = claim

      const covering = registeredClaims.filter((registered) => pathCovered(path, registered.path))
      if (covering.length === 0) {
        issues.add({
          code: OVER_ASKING_CODES.CLAIM_NOT_REGISTERED,
          path: queryPath,
          message: `${label} asks for the claim ${JSON.stringify(path)}, which is not registered`,
        })
        return
      }

      // A registered claim without values allows any value
      const requestedValues = claim.values
      const allowed = covering.some(
        (registered) => !registered.values || requestedValues?.every((value) => registered.values?.includes(value))
      )
      if (!allowed) {
        const registeredValues = covering.flatMap((registered) => registered.values ?? [])
        issues.add({
          code: OVER_ASKING_CODES.CLAIM_VALUES_NOT_REGISTERED,
          path: [...queryPath, 'values'],
          message: `${label} asks for the claim ${JSON.stringify(path)} with ${
            requestedValues ? `the values ${JSON.stringify(requestedValues)}` : 'any value'
          }, but only ${JSON.stringify(registeredValues)} are registered`,
        })
      }
    })
  })

  return issues.result()
}
