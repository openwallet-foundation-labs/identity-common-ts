import { base64url, type Finding, type FindingSeverity, hasErrorFindings, isMediaType } from '@owf/identity-common'
import { JWT_STATUS_LIST_TYPE } from './jwt-types'
import { StatusList } from './status-list'
import { type BitsPerStatus, MediaTypes } from './types'

/**
 * Codes of the findings of {@link validateStatusListJwt}, with the section of
 * draft-ietf-oauth-status-list-16 as `requirement` where a check has one.
 */
export const STATUS_LIST_VALIDATION_CODES = {
  /** The header or the payload is not a JSON object */
  INVALID_STRUCTURE: 'invalid_structure',
  /** `typ` is missing or not `statuslist+jwt` (Section 5.1) */
  INVALID_TYP: 'invalid_typ',
  /** `alg` is missing (RFC 7515 Section 4.1.1) */
  MISSING_ALG: 'missing_alg',
  /** `sub` is missing or not a string (Section 5.1) */
  MISSING_SUBJECT: 'missing_subject',
  /** `sub` differs from the `uri` the token was referenced by (Section 5.1) */
  SUBJECT_MISMATCH: 'subject_mismatch',
  /** `iat` is missing (Section 5.1) */
  MISSING_ISSUED_AT: 'missing_issued_at',
  /** `iat`, `exp` or `nbf` is not a number of seconds */
  INVALID_TIME_CLAIM: 'invalid_time_claim',
  /** `iat` is in the future */
  ISSUED_IN_FUTURE: 'issued_in_future',
  /** `nbf` is in the future */
  NOT_YET_VALID: 'not_yet_valid',
  /** `exp` is missing, which is RECOMMENDED (Section 5.1) */
  MISSING_EXPIRATION_TIME: 'missing_expiration_time',
  /** `exp` is in the past */
  EXPIRED: 'expired',
  /** `exp` is at or before `iat` */
  EXPIRES_BEFORE_ISSUED: 'expires_before_issued',
  /** `ttl` is missing, which is RECOMMENDED (Section 5.1) */
  MISSING_TTL: 'missing_ttl',
  /** `ttl` is not a positive number (Section 5.1) */
  INVALID_TTL: 'invalid_ttl',
  /** `status_list` is missing or not an object (Section 5.1) */
  MISSING_STATUS_LIST: 'missing_status_list',
  /** `bits` is not 1, 2, 4 or 8 (Section 4.2) */
  INVALID_BITS: 'invalid_bits',
  /** `lst` is not a base64url encoded, ZLIB compressed byte array (Section 4.2) */
  INVALID_LST: 'invalid_lst',
  /** `aggregation_uri` is not a URI (Section 4.2) */
  INVALID_AGGREGATION_URI: 'invalid_aggregation_uri',
} as const

/** A code of a finding of {@link validateStatusListJwt} */
export type StatusListValidationCode = (typeof STATUS_LIST_VALIDATION_CODES)[keyof typeof STATUS_LIST_VALIDATION_CODES]

export type StatusListFinding = Finding<StatusListValidationCode>

export interface ValidateStatusListJwtOptions {
  /** The `uri` of the status list reference the token was fetched for. Without it, `sub` is not compared. */
  uri?: string
  /** Reference time for `iat`, `nbf` and `exp`; defaults to now. Pass `false` to skip these checks. */
  now?: Date | false
  /** Clock tolerance applied to `iat`, `nbf` and `exp`, in seconds. Defaults to 30. */
  skewSeconds?: number
}

export interface StatusListJwtValidationResult {
  /** `true` when there are no errors; warnings do not affect validity */
  valid: boolean
  /** Findings with paths starting at `header` or `payload` */
  findings: StatusListFinding[]
  /** The status list, when `bits` and `lst` could be decoded */
  statusList?: StatusList
}

const C = STATUS_LIST_VALIDATION_CODES
const BITS: readonly number[] = [1, 2, 4, 8] satisfies BitsPerStatus[]
const BASE64URL = /^[A-Za-z0-9_-]*$/

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value)

// Not URL.canParse, which not every runtime of the package has
function isUri(value: string): boolean {
  try {
    new URL(value)
    return true
  } catch {
    return false
  }
}

/**
 * Check the header and the claims of a Status List Token in JWT format, reporting every
 * problem as a finding rather than throwing at the first one. Use it to inspect a token;
 * a verifier uses {@link verifyStatusListJwtHeader} and {@link verifyStatusListJwtClaims}
 * after verifying the signature, which this does not do.
 *
 * @see https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-16.html#section-5.1
 */
export function validateStatusListJwt(
  header: unknown,
  payload: unknown,
  { uri, now = new Date(), skewSeconds = 30 }: ValidateStatusListJwtOptions = {}
): StatusListJwtValidationResult {
  const findings: StatusListFinding[] = []
  const add = (
    severity: FindingSeverity,
    code: StatusListValidationCode,
    path: (string | number)[],
    message: string,
    requirement?: string
  ) => findings.push({ severity, code, path, message, ...(requirement ? { requirement } : {}) })
  const result = (statusList?: StatusList): StatusListJwtValidationResult => ({
    valid: !hasErrorFindings(findings),
    findings,
    ...(statusList ? { statusList } : {}),
  })

  if (!isRecord(header)) add('error', C.INVALID_STRUCTURE, ['header'], 'The header is not a JSON object')
  if (!isRecord(payload)) add('error', C.INVALID_STRUCTURE, ['payload'], 'The payload is not a JSON object')
  if (!isRecord(header) || !isRecord(payload)) return result()

  // Header
  const { typ, alg } = header
  if (typeof typ !== 'string') {
    add('error', C.INVALID_TYP, ['header', 'typ'], `typ is missing, it must be ${JWT_STATUS_LIST_TYPE}`, 'Section 5.1')
  } else if (!isMediaType(typ.includes('/') ? typ : `application/${typ}`, MediaTypes.StatusListJwt)) {
    add('error', C.INVALID_TYP, ['header', 'typ'], `typ is ${typ}, it must be ${JWT_STATUS_LIST_TYPE}`, 'Section 5.1')
  }
  if (typeof alg !== 'string') add('error', C.MISSING_ALG, ['header', 'alg'], 'alg is missing (RFC 7515 Section 4.1.1)')

  // Subject
  const { sub } = payload
  if (typeof sub !== 'string') {
    add('error', C.MISSING_SUBJECT, ['payload', 'sub'], 'sub must be the URI of the status list token', 'Section 5.1')
  } else if (uri !== undefined && sub !== uri) {
    add('error', C.SUBJECT_MISMATCH, ['payload', 'sub'], `sub must be equal to the uri ${uri}`, 'Section 5.1')
  }

  // Times
  const skewMs = skewSeconds * 1000
  const time = (claim: 'iat' | 'nbf' | 'exp'): Date | undefined => {
    const value = payload[claim]
    if (value === undefined) return undefined
    if (typeof value !== 'number' || !Number.isFinite(value)) {
      add('error', C.INVALID_TIME_CLAIM, ['payload', claim], `${claim} must be a number of seconds since the epoch`)
      return undefined
    }
    return new Date(value * 1000)
  }
  const issuedAt = time('iat')
  const notBefore = time('nbf')
  const expirationTime = time('exp')

  if (payload.iat === undefined) {
    add('error', C.MISSING_ISSUED_AT, ['payload', 'iat'], 'iat is missing', 'Section 5.1')
  }
  if (payload.exp === undefined) {
    add('warning', C.MISSING_EXPIRATION_TIME, ['payload', 'exp'], 'exp is missing, which is RECOMMENDED', 'Section 5.1')
  }
  if (issuedAt && expirationTime && expirationTime <= issuedAt) {
    add('error', C.EXPIRES_BEFORE_ISSUED, ['payload', 'exp'], 'exp must be after iat')
  }
  if (now !== false) {
    if (issuedAt && issuedAt.getTime() - skewMs > now.getTime()) {
      add('error', C.ISSUED_IN_FUTURE, ['payload', 'iat'], `iat ${issuedAt.toISOString()} is in the future`)
    }
    if (notBefore && notBefore.getTime() - skewMs > now.getTime()) {
      add('error', C.NOT_YET_VALID, ['payload', 'nbf'], `The token is not valid before ${notBefore.toISOString()}`)
    }
    if (expirationTime && expirationTime.getTime() + skewMs <= now.getTime()) {
      add('error', C.EXPIRED, ['payload', 'exp'], `The token expired at ${expirationTime.toISOString()}`)
    }
  }

  // Time to live
  const { ttl } = payload
  if (ttl === undefined) {
    add('warning', C.MISSING_TTL, ['payload', 'ttl'], 'ttl is missing, which is RECOMMENDED', 'Section 5.1')
  } else if (typeof ttl !== 'number' || !(ttl > 0)) {
    add('error', C.INVALID_TTL, ['payload', 'ttl'], 'ttl must be a positive number of seconds', 'Section 5.1')
  }

  // Status list
  const statusList = payload.status_list
  if (!isRecord(statusList)) {
    add('error', C.MISSING_STATUS_LIST, ['payload', 'status_list'], 'status_list must be an object', 'Section 5.1')
    return result()
  }
  const { bits, lst, aggregation_uri: aggregationUri } = statusList
  const path = ['payload', 'status_list']
  const validBits = typeof bits === 'number' && BITS.includes(bits)
  if (!validBits) {
    add('error', C.INVALID_BITS, [...path, 'bits'], 'bits must be 1, 2, 4 or 8', 'Section 4.2')
  }
  if (aggregationUri !== undefined && (typeof aggregationUri !== 'string' || !isUri(aggregationUri))) {
    add(
      'error',
      C.INVALID_AGGREGATION_URI,
      [...path, 'aggregation_uri'],
      'aggregation_uri must be a URI',
      'Section 4.2'
    )
  }

  if (typeof lst !== 'string' || !BASE64URL.test(lst)) {
    add('error', C.INVALID_LST, [...path, 'lst'], 'lst must be a base64url encoded string', 'Section 4.2')
    return result()
  }
  if (!validBits) return result()
  try {
    return result(
      StatusList.decompressStatusListFromBytes(
        base64url.decode(lst),
        bits as BitsPerStatus,
        typeof aggregationUri === 'string' ? aggregationUri : undefined
      )
    )
  } catch {
    add('error', C.INVALID_LST, [...path, 'lst'], 'lst is not a ZLIB compressed byte array', 'Section 4.2')
    return result()
  }
}
