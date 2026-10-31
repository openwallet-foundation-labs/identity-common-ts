/**
 * Over-asking check
 *
 * Compares the DCQL query of an OpenID4VP request with the credentials and claims a
 * Wallet-Relying Party registered, as listed in the `credentials` of its WRPRC (ETSI TS
 * 119 475 Table 9), which follow the shape of a DCQL Credential Query.
 */

import { type Finding, hasErrorFindings } from '@owf/identity-common'

/** Codes of the findings of {@link checkOverAsking} */
export const OVER_ASKING_CODES = {
  /** The query is not a DCQL query with a `credentials` array */
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

export type OverAskingFinding = Finding<OverAskingCode>

export interface OverAskingResult {
  /** `true` when the request asks for nothing beyond the registration */
  valid: boolean
  /** Findings with paths into the DCQL query, e.g. `['credentials', 0, 'claims', 2]` */
  findings: OverAskingFinding[]
}

type ClaimPath = (string | number | null)[]
type ClaimValue = string | number | boolean

/** A claims query, as a claims path pointer or in the mdoc `namespace`/`claim_name` form of earlier drafts */
interface RequestedClaim {
  path?: ClaimPath
  namespace?: string
  claim_name?: string
  values?: ClaimValue[]
}

/** A registered credential, from the `credentials` of a WRPRC. Either spelling of the claims array is read. */
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

function claimPath(claim: RequestedClaim): ClaimPath | undefined {
  if (Array.isArray(claim.path)) return claim.path
  if (typeof claim.namespace === 'string' && typeof claim.claim_name === 'string') {
    return [claim.namespace, claim.claim_name]
  }
  return undefined
}

const describeMeta = (meta: unknown) => (isRecord(meta) && Object.keys(meta).length > 0 ? JSON.stringify(meta) : '{}')

/**
 * Check that an OpenID4VP request asks for no credential or claim beyond what the
 * Wallet-Relying Party registered in its WRPRC.
 *
 * A requested credential needs a registered one of the same format whose `meta` the
 * request stays within. Each requested claim then needs a registered claim of such a
 * credential with an equal or a parent path; if that claim lists `values`, the request
 * has to ask for some of these values only. A credential query without `claims` asks for
 * no selectively disclosable claims, so only the credential is checked.
 *
 * A registered credential without claims is reported as a warning for each credential
 * query with claims, as the registration does not say which claims are allowed.
 *
 * @param query The DCQL query of the request, e.g. its `dcql_query` parameter or a parsed `DcqlQuery`
 * @param registeredCredentials The `credentials` of the WRPRC payload
 */
export function checkOverAsking(
  query: unknown,
  registeredCredentials: readonly RegisteredCredential[] = []
): OverAskingResult {
  const findings: OverAskingFinding[] = []
  const result = (): OverAskingResult => ({ valid: !hasErrorFindings(findings), findings })

  if (!isRecord(query) || !Array.isArray(query.credentials)) {
    findings.push({
      severity: 'error',
      code: OVER_ASKING_CODES.INVALID_QUERY,
      path: ['credentials'],
      message: 'The query is not a DCQL query: credentials must be an array of credential queries',
    })
    return result()
  }

  query.credentials.forEach((credential: unknown, credentialIndex: number) => {
    const credentialPath = ['credentials', credentialIndex]
    if (!isRecord(credential) || typeof credential.format !== 'string') {
      findings.push({
        severity: 'error',
        code: OVER_ASKING_CODES.INVALID_QUERY,
        path: credentialPath,
        message: 'A credential query must be an object with a format',
      })
      return
    }

    const label = typeof credential.id === 'string' ? `Credential query ${credential.id}` : 'The credential query'
    const sameFormat = registeredCredentials.filter((registered) => registered.format === credential.format)
    const matching = sameFormat.filter((registered) => metaCovered(credential.meta ?? {}, registered.meta))
    if (matching.length === 0) {
      findings.push({
        severity: 'error',
        code: OVER_ASKING_CODES.CREDENTIAL_NOT_REGISTERED,
        path: sameFormat.length === 0 ? [...credentialPath, 'format'] : [...credentialPath, 'meta'],
        message:
          sameFormat.length === 0
            ? `${label} asks for a ${credential.format} credential, and none of this format is registered`
            : `${label} asks for a ${credential.format} credential with meta ${describeMeta(credential.meta)}, which no registered ${credential.format} credential covers`,
      })
      return
    }

    if (!Array.isArray(credential.claims)) return

    const registeredClaims = matching.flatMap((registered) => registered.claim ?? registered.claims ?? [])
    if (matching.some((registered) => !(registered.claim ?? registered.claims))) {
      findings.push({
        severity: 'warning',
        code: OVER_ASKING_CODES.CLAIMS_NOT_LISTED,
        path: [...credentialPath, 'claims'],
        message: `The registered ${credential.format} credential lists no claims, so the claims of ${label.toLowerCase()} cannot be confirmed`,
      })
      return
    }

    credential.claims.forEach((claim: unknown, claimIndex: number) => {
      const path = isRecord(claim) ? claimPath(claim as RequestedClaim) : undefined
      const findingPath = [...credentialPath, 'claims', claimIndex]
      if (!path) {
        findings.push({
          severity: 'error',
          code: OVER_ASKING_CODES.INVALID_QUERY,
          path: findingPath,
          message: 'A claims query must have a path, or a namespace and a claim_name',
        })
        return
      }

      const covering = registeredClaims.filter((registered) => pathCovered(path, registered.path))
      if (covering.length === 0) {
        findings.push({
          severity: 'error',
          code: OVER_ASKING_CODES.CLAIM_NOT_REGISTERED,
          path: findingPath,
          message: `${label} asks for the claim ${JSON.stringify(path)}, which is not registered`,
        })
        return
      }

      // A registered claim without values allows any value
      const requestedValues = (claim as RequestedClaim).values
      const allowed = covering.some(
        (registered) => !registered.values || requestedValues?.every((value) => registered.values?.includes(value))
      )
      if (!allowed) {
        const registeredValues = covering.flatMap((registered) => registered.values ?? [])
        findings.push({
          severity: 'error',
          code: OVER_ASKING_CODES.CLAIM_VALUES_NOT_REGISTERED,
          path: [...findingPath, 'values'],
          message: `${label} asks for the claim ${JSON.stringify(path)} with ${
            requestedValues ? `the values ${JSON.stringify(requestedValues)}` : 'any value'
          }, but only ${JSON.stringify(registeredValues)} are registered`,
        })
      }
    })
  })

  return result()
}
