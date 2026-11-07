import { base64url, type MarkOptional } from '@owf/identity-common'
import {
  type DecodeJwtResult,
  decodeJwt,
  jwsHeaderFromSigner,
  type SignJwtOptions,
  type SignJwtResult,
  signJwt,
  type VerifyJwtClaimsOptions,
  type VerifyJwtOptions,
  type VerifyJwtResult,
  verifyJwt,
  verifyJwtClaims,
} from '@owf/jose'
import z from 'zod'
import {
  JWT_STATUS_LIST_TYPE,
  type StatusListJwtPayload,
  zStatusListJwtHeader,
  zStatusListJwtPayload,
} from './jwt-types'
import { StatusList, verifyStatusValid } from './status-list'

type StatusListJwtHeaderSchema = typeof zStatusListJwtHeader
type StatusListJwtPayloadSchema = typeof zStatusListJwtPayload

// Only `statuslist+jwt` is signed, while decoding also accepts other forms of it, such as `application/statuslist+jwt`
const zStatusListJwtHeaderToSign = zStatusListJwtHeader.extend({ typ: z.literal(JWT_STATUS_LIST_TYPE) })

/** The header of a Status List Token to sign. `typ` defaults to `statuslist+jwt`. */
export type CreateStatusListJwtHeader = MarkOptional<z.input<StatusListJwtHeaderSchema>, 'typ'>

/** The claims of a Status List Token to sign. `status_list` is created from the list. */
export type CreateStatusListJwtPayload = MarkOptional<z.input<StatusListJwtPayloadSchema>, 'status_list'>

export type SignStatusListJwtOptions = Omit<
  SignJwtOptions<StatusListJwtHeaderSchema, StatusListJwtPayloadSchema>,
  'header' | 'payload' | 'headerSchema' | 'payloadSchema'
> & {
  statusList: StatusList
  payload: CreateStatusListJwtPayload

  /** Extra header parameters. `alg` and the parameters that identify the signer come from the signer. */
  header?: MarkOptional<CreateStatusListJwtHeader, 'alg'>
}

/**
 * Signs a Status List Token in JWT format carrying `statusList`.
 *
 * @throws JoseValidationError if the header or payload is not valid for a Status List Token.
 * @throws JoseInvalidArgumentError if the header identifies another signer than `signer`, see `signCompactJws`.
 */
export async function signStatusListJwt({
  statusList,
  payload,
  header = {},
  ...options
}: SignStatusListJwtOptions): Promise<SignJwtResult<typeof zStatusListJwtHeaderToSign, StatusListJwtPayloadSchema>> {
  // A parameter the header leaves undefined does not remove the one the signer gives
  const definedHeader = Object.fromEntries(Object.entries(header).filter(([, value]) => value !== undefined))

  return signJwt({
    ...options,
    header: { ...jwsHeaderFromSigner(options.signer), typ: JWT_STATUS_LIST_TYPE, ...definedHeader },
    payload: {
      ...payload,
      status_list: {
        bits: statusList.getBitsPerStatus(),
        lst: base64url.encode(statusList.compressStatusListToBytes()),
        ...(statusList.aggregationUri !== undefined && { aggregation_uri: statusList.aggregationUri }),
      },
    },
    headerSchema: zStatusListJwtHeaderToSign,
    payloadSchema: zStatusListJwtPayload,
  })
}

export type DecodeStatusListJwtResult = DecodeJwtResult<StatusListJwtHeaderSchema, StatusListJwtPayloadSchema> & {
  /**
   * Decompressed on first read, so read it only once the token verified. Throws a `StatusListValidationError`
   * when `lst` is not a compressed status list.
   */
  readonly statusList: StatusList
}

/**
 * Decodes a Status List Token in JWT format without verifying the signature, see {@link verifyStatusListJwt}.
 *
 * @throws JoseParseError if the token is not well-formed.
 * @throws JoseValidationError if the token is not a Status List Token.
 */
export function decodeStatusListJwt(jwt: string): DecodeStatusListJwtResult {
  const decoded = decodeJwt({ jwt, headerSchema: zStatusListJwtHeader, payloadSchema: zStatusListJwtPayload })
  const { bits, lst, aggregation_uri } = decoded.payload.status_list

  let statusList: StatusList | undefined
  return {
    ...decoded,
    get statusList() {
      if (statusList) return statusList
      statusList = StatusList.decompressStatusListFromBytes(base64url.decode(lst), bits, aggregation_uri)
      return statusList
    },
  }
}

export type VerifyStatusListJwtClaimsOptions = Omit<VerifyJwtClaimsOptions, 'expectedSubject'> & {
  /** The `uri` of the status list reference, which `sub` must equal. */
  uri: string
}

/**
 * Verifies the claims of a Status List Token in JWT format, with `sub` expected to be `uri`.
 *
 * @throws JoseValidationError with an issue for each claim that does not verify.
 * @see https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-16.html#section-8.3
 */
export function verifyStatusListJwtClaims(
  payload: StatusListJwtPayload,
  { uri, ...options }: VerifyStatusListJwtClaimsOptions
): void {
  verifyJwtClaims(payload, { ...options, expectedSubject: uri })
}

export type VerifyStatusListJwtOptions = Omit<
  VerifyJwtOptions<StatusListJwtHeaderSchema, StatusListJwtPayloadSchema>,
  'jwt' | 'headerSchema' | 'payloadSchema' | 'expectedSubject' | 'understoodCriticalParameters'
> & {
  /** The compact token, or a decoded one, of which only `compact` is used. */
  jwt: string | DecodeStatusListJwtResult

  /** The `uri` of the status list reference, which `sub` must equal. */
  uri: string

  /** When given, the status at this index must be `Valid`. */
  idx?: number
}

export type VerifyStatusListJwtResult = VerifyJwtResult<StatusListJwtHeaderSchema, StatusListJwtPayloadSchema> & {
  statusList: StatusList
}

/**
 * Verifies a Status List Token in JWT format: the signature, the claims with `sub` expected to be
 * `uri`, and the status at `idx` when given. The list is decompressed only once the token verified.
 *
 * @throws JoseParseError, JoseValidationError or JoseVerificationError if the token does not verify.
 * @throws StatusListValidationError if the status list cannot be decompressed (`invalid_status_list`), or `idx`
 *   is not in it (`index_out_of_range`) or its status is not `Valid` (`status_not_valid`).
 */
export async function verifyStatusListJwt({
  jwt,
  uri,
  idx,
  ...options
}: VerifyStatusListJwtOptions): Promise<VerifyStatusListJwtResult> {
  const decoded = decodeStatusListJwt(typeof jwt === 'string' ? jwt : jwt.compact)

  const verified = await verifyJwt<StatusListJwtHeaderSchema, StatusListJwtPayloadSchema>({
    ...options,
    jwt: decoded,
    expectedSubject: uri,
    errorMessage: options.errorMessage ?? 'Error during verification of the Status List Token.',
  })

  const statusList = decoded.statusList
  if (idx !== undefined) verifyStatusValid(statusList, idx)

  return { ...verified, statusList }
}
