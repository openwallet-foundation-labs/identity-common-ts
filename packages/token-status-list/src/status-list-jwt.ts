import { base64url } from '@owf/identity-common'
import {
  type DecodeJwtResult,
  decodeJwt,
  JoseInvalidArgumentError,
  type Jwk,
  type JwsSigner,
  type JwsSignerMethod,
  jwsHeaderFromSigner,
  type MarkOptional,
  parseWithErrorHandling,
  type SignJwtOptions,
  type SignJwtResult,
  signJwt,
  type VerifyJwtClaimsOptions,
  type VerifyJwtOptions,
  type VerifyJwtResult,
  verifyJwsSignature,
  verifyJwtClaims,
  zJwkThumbprintComponents,
} from '@owf/jose'
import type z from 'zod'
import {
  JWT_STATUS_LIST_TYPE,
  type StatusListJwtHeaderParameters,
  type StatusListJwtPayload,
  zStatusListJwtHeader,
  zStatusListJwtPayload,
} from './jwt-types'
import { StatusList } from './status-list'
import { StatusListEntryNotValidError, StatusListError } from './status-list-error'
import { StatusType } from './types'

type StatusListJwtHeaderSchema = typeof zStatusListJwtHeader
type StatusListJwtPayloadSchema = typeof zStatusListJwtPayload

/** The header of a Status List Token to create. `typ` defaults to `statuslist+jwt`. */
export type CreateStatusListJwtHeader = MarkOptional<z.input<StatusListJwtHeaderSchema>, 'typ'>

/** The claims of a Status List Token to create. `status_list` is always created from the list. */
export type CreateStatusListJwtPayload = MarkOptional<z.input<StatusListJwtPayloadSchema>, 'status_list'>

/**
 * Creates the header and payload of a Status List Token in JWT format, carrying `list`.
 *
 * Both are validated against the schemas a token is decoded with, so a header whose `typ` says the
 * token is something else, or a payload without the `sub` and `iat` a Status List Token requires,
 * is rejected here rather than by the verifier.
 *
 * The signer is not known here, so the header only identifies it when `header` does: spread
 * `jwsHeaderFromSigner(signer)` of `@owf/jose` into it, or sign with {@link signStatusListJwt}, which
 * adds those parameters itself.
 *
 * @throws JoseValidationError if the header or payload is not valid for a Status List Token.
 */
export function createHeaderAndPayload(
  list: StatusList,
  payload: CreateStatusListJwtPayload,
  header: CreateStatusListJwtHeader
): { header: StatusListJwtHeaderParameters; payload: StatusListJwtPayload } {
  return {
    header: parseWithErrorHandling(
      zStatusListJwtHeader,
      { ...header, typ: header.typ ?? JWT_STATUS_LIST_TYPE },
      'Unable to create the status list token, invalid header'
    ),
    payload: parseWithErrorHandling(
      zStatusListJwtPayload,
      {
        ...payload,
        status_list: {
          bits: list.getBitsPerStatus(),
          lst: base64url.encode(list.compressStatusListToBytes()),
          ...(list.aggregationUri !== undefined && { aggregation_uri: list.aggregationUri }),
        },
      },
      'Unable to create the status list token, invalid payload'
    ),
  }
}

export type SignStatusListJwtOptions = Omit<
  SignJwtOptions<StatusListJwtHeaderSchema, StatusListJwtPayloadSchema>,
  'header' | 'payload' | 'headerSchema' | 'payloadSchema'
> & {
  /** The status list to carry in the `status_list` claim. */
  statusList: StatusList

  /** The claims of the token. `status_list` is always created from {@link statusList}. */
  payload: CreateStatusListJwtPayload

  /**
   * The header of the token. `typ` defaults to `statuslist+jwt`, `alg` is taken from the signer.
   *
   * The parameters that identify the signer are added from the signer, as `jwsHeaderFromSigner` of
   * `@owf/jose` gives them: `x5c` for an x5c signer, `jwk` for a jwk signer, the DID URL as `kid` for a
   * did signer, `kid` and `trust_chain` for a federation signer, and the `kid` of a custom signer that
   * has one. A verifier establishes the signer from them. The header can repeat them, but not
   * contradict them, see {@link signStatusListJwt}. A parameter set to `undefined` does not remove one.
   */
  header?: MarkOptional<CreateStatusListJwtHeader, 'alg'>
}

/** Whether two lists hold the same values, in the same order. */
const isSameList = (a: ReadonlyArray<string>, b: ReadonlyArray<string>): boolean =>
  a.length === b.length && a.every((value, index) => value === b[index])

/**
 * Whether two JWKs are the same key: whether the members their RFC 7638 thumbprint is computed over
 * match, whatever other members they carry. RFC 7638 only names those members for the key types it
 * registers, so two keys of another type are the same key only when all their members are.
 */
const isSameKey = (a: Jwk, b: Jwk): boolean => {
  const componentsA = zJwkThumbprintComponents.safeParse(a)
  const componentsB = zJwkThumbprintComponents.safeParse(b)
  if (componentsA.success && componentsB.success) {
    return JSON.stringify(componentsA.data) === JSON.stringify(componentsB.data)
  }
  if (componentsA.success || componentsB.success) return false

  const membersOf = (jwk: Jwk) => Object.keys(jwk).filter((member) => jwk[member] !== undefined)
  const membersA = membersOf(a)
  return (
    membersA.length === membersOf(b).length &&
    membersA.every((member) => JSON.stringify(a[member]) === JSON.stringify(b[member]))
  )
}

/**
 * Rejects a header that identifies another signer than the one the token is signed with. A verifier
 * establishes the signer from the header (`jwsSignerFromHeader` of `@owf/jose`), so the token would
 * claim a key it was not signed with.
 *
 * The header has to carry what `jwsHeaderFromSigner` gives for the signer: the same `kid`, `x5c` and
 * `trust_chain`, and a `jwk` that is the same key. A did, federation, jwk or x5c signer is identified
 * that way only. Next to it, a `jwk`, `x5c`, `trust_chain` or a DID URL as `kid` identifies the signer
 * by another method, and whether that names the same key cannot be told; a verifier rejects such a
 * header too. When `iss` is a DID, a `kid` that is a fragment (`#key-1`) is such a DID URL as well: a
 * verifier resolves it against `iss`. A custom signer is established out of band, so the header can
 * identify it in any way that keeps its `kid`.
 *
 * `jwsHeaderFromSigner` leaves the `kid` of an x5c or jwk signer out: it says which key the callback
 * signs with. A `kid` in the header of such a token is a hint that does not contradict the signer,
 * unless it identifies a did signer.
 *
 * @throws JoseInvalidArgumentError if the header identifies another signer.
 */
function assertHeaderIdentifiesSigner(
  header: StatusListJwtHeaderParameters,
  signer: JwsSigner,
  issuer: string | undefined
): void {
  const signerHeader: {
    kid?: string
    jwk?: Jwk
    x5c?: ReadonlyArray<string>
    trust_chain?: ReadonlyArray<string>
  } = jwsHeaderFromSigner(signer)

  if (signerHeader.kid !== undefined && header.kid !== signerHeader.kid) {
    throw new JoseInvalidArgumentError(
      `Unable to sign the status list token, the kid in the header is '${header.kid}', but the signer is identified by kid '${signerHeader.kid}'.`
    )
  }

  if (signerHeader.x5c !== undefined && (header.x5c === undefined || !isSameList(header.x5c, signerHeader.x5c))) {
    throw new JoseInvalidArgumentError(
      'Unable to sign the status list token, the x5c in the header is not the certificate chain of the signer.'
    )
  }

  if (
    signerHeader.trust_chain !== undefined &&
    (header.trust_chain === undefined || !isSameList(header.trust_chain, signerHeader.trust_chain))
  ) {
    throw new JoseInvalidArgumentError(
      'Unable to sign the status list token, the trust_chain in the header is not the trust chain of the signer.'
    )
  }

  if (signerHeader.jwk !== undefined && (header.jwk === undefined || !isSameKey(header.jwk, signerHeader.jwk))) {
    throw new JoseInvalidArgumentError(
      'Unable to sign the status list token, the jwk in the header is not the public key of the signer.'
    )
  }

  if (signer.method === 'custom') return

  // The parameters a verifier establishes the signer from, and the signer method each identifies. A
  // `kid` identifies a did signer when it is a DID URL, or a fragment that `jwsSignerFromHeader`
  // resolves against a DID in `iss`.
  const kidIdentifiesDid =
    header.kid?.startsWith('did:') === true ||
    (header.kid?.startsWith('#') === true && issuer?.startsWith('did:') === true)
  const identifiedMethods: Array<[parameter: string, method: JwsSignerMethod, present: boolean]> = [
    ['x5c', 'x5c', header.x5c !== undefined],
    ['trust_chain', 'federation', header.trust_chain !== undefined],
    ['kid', 'did', kidIdentifiesDid],
    ['jwk', 'jwk', header.jwk !== undefined],
  ]
  const otherMethod = identifiedMethods.find(([, method, present]) => present && method !== signer.method)
  if (otherMethod) {
    const [parameter, method] = otherMethod
    throw new JoseInvalidArgumentError(
      `Unable to sign the status list token, the '${parameter}' in the header identifies a signer with method '${method}', but the signer has method '${signer.method}'.`
    )
  }
}

/**
 * Create and sign a Status List Token in JWT format carrying `statusList`: the header and payload
 * are created with {@link createHeaderAndPayload} and signed with `signJwt`.
 *
 * The header identifies the signer the way `jwsHeaderFromSigner` of `@owf/jose` does, so that a
 * verifier can establish the signer from it. A `header` that contradicts the signer is rejected rather
 * than signed: a `kid`, `x5c` or `trust_chain` with another value than the signer's, or a `jwk` that is
 * another key. So is one that identifies a did, federation, jwk or x5c signer by another signer method
 * as well, such as a `jwk` next to the `x5c` of an x5c signer.
 *
 * @throws JoseValidationError if the header or payload is not valid for a Status List Token.
 * @throws JoseInvalidArgumentError if the header identifies another signer than `signer`.
 */
export async function signStatusListJwt({
  statusList,
  payload,
  header = {},
  ...options
}: SignStatusListJwtOptions): Promise<SignJwtResult<StatusListJwtHeaderSchema, StatusListJwtPayloadSchema>> {
  // A parameter the header leaves undefined does not remove the one the signer gives
  const definedHeader = Object.fromEntries(
    Object.entries(header).filter(([, value]) => value !== undefined)
  ) as typeof header

  const created = createHeaderAndPayload(statusList, payload, {
    ...jwsHeaderFromSigner(options.signer),
    ...definedHeader,
    alg: options.signer.alg,
  })
  assertHeaderIdentifiesSigner(created.header, options.signer, created.payload.iss)

  return signJwt({
    ...options,
    header: created.header,
    payload: created.payload,
    headerSchema: zStatusListJwtHeader,
    payloadSchema: zStatusListJwtPayload,
  })
}

export type DecodeStatusListJwtResult = DecodeJwtResult<StatusListJwtHeaderSchema, StatusListJwtPayloadSchema> & {
  /**
   * The status list carried in the `status_list` claim, decompressed when it is first read. Reading
   * it throws a `StatusListError` when `lst` is not a compressed status list.
   *
   * Reading it before the signature is verified decompresses `lst` before it is known to be the
   * issuer's, and a few kilobytes of it can inflate to a list of any size.
   */
  readonly statusList: StatusList
}

/**
 * Decodes a Status List Token in JWT format, validating its header and payload against
 * `zStatusListJwtHeader` and `zStatusListJwtPayload`. The signature is not verified here, see
 * {@link verifyStatusListJwt}.
 *
 * A token without the `statuslist+jwt` type is rejected here, so before its signature is verified:
 * without that check a JWT the issuer signed for another purpose with the same key could be
 * presented as a status list.
 *
 * The status list itself is only decompressed once `statusList` is read, so a token can be decoded —
 * to select the key to verify it with, say — without decompressing a list nobody has verified yet.
 *
 * @throws JoseParseError if the token is not a well-formed Status List Token. `JoseValidationError`,
 *   a subclass of it, says the token is well-formed but is not a Status List Token.
 */
export function decodeStatusListJwt(jwt: string): DecodeStatusListJwtResult {
  const decoded = decodeJwt({ jwt, headerSchema: zStatusListJwtHeader, payloadSchema: zStatusListJwtPayload })
  const { bits, lst, aggregation_uri } = decoded.payload.status_list

  let statusList: StatusList | undefined
  return {
    ...decoded,
    get statusList() {
      if (statusList) return statusList
      try {
        statusList = StatusList.decompressStatusListFromBytes(base64url.decode(lst), bits, aggregation_uri)
      } catch (error) {
        throw Object.assign(new StatusListError('The status list token has no valid status_list claim'), {
          cause: error,
        })
      }
      return statusList
    },
  }
}

/**
 * The options {@link verifyStatusListJwtClaims} takes: the generic JWT ones, with `expectedSubject`
 * replaced by the `uri` it has to be equal to.
 */
export type VerifyStatusListJwtClaimsOptions = Omit<VerifyJwtClaimsOptions, 'expectedSubject'> & {
  /** The `uri` of the status list reference the token was fetched for, which `sub` must equal. */
  uri: string
}

/**
 * Verify the claims of a Status List Token in JWT format: the validity window, and that `sub` is the
 * uri the token was published for — without that check a token published for one uri can be
 * replayed for another under the same issuer. That `sub` and `iat` are present is already
 * guaranteed by `zStatusListJwtPayload`.
 *
 * A profile that makes a further claim mandatory — ISO/IEC 18013-5 second edition § 12.3.6.3 does
 * for `exp`, on the revocation list of an MSO — adds it through `requiredClaims`.
 *
 * The CWT serialization verifies the same rules through `StatusListCwtPayload.verifyClaims`.
 *
 * @throws JoseClaimVerificationError if a claim does not verify. Its `claim` and `reason` say which
 *   claim it was and what was wrong with it.
 * @see https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-16.html#section-5
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
  /**
   * The Status List Token: the compact serialization, or the result of {@link decodeStatusListJwt}
   * when the token had to be inspected before deciding how to verify it.
   *
   * Only the `compact` serialization of a decoded token is used: it is decoded again, so that the
   * header, claims and status list that are verified and returned are the ones the signature covers,
   * whatever happened to the decoded object in the meantime.
   */
  jwt: string | DecodeStatusListJwtResult

  /** The `uri` of the status list reference the token was fetched for, which `sub` must equal. */
  uri: string

  /** When given, the status at this index is verified to be `Valid`. */
  idx?: number
}

export type VerifyStatusListJwtResult = VerifyJwtResult<StatusListJwtHeaderSchema, StatusListJwtPayloadSchema> & {
  /** The status list carried in the `status_list` claim. */
  statusList: StatusList
}

/**
 * Verify a Status List Token in JWT format completely: its signature, its claims, and — when `idx`
 * is given — that the status at that index is `Valid`. This is what a verifier resolving a status
 * list reference wants, and the only form in which the claims mean anything, since they are only
 * the issuer's if the signature verifies.
 *
 * The claims are verified through {@link verifyStatusListJwtClaims}, so the rules for a Status List
 * Token's claims are the same whether they are verified on their own or as part of the token.
 *
 * The status list is decompressed only once the signature and the claims have verified: until then
 * `lst` is not known to be the issuer's, and a few kilobytes of it can inflate to a list of any size.
 *
 * The CWT serialization is verified the same way through `StatusListCwt.verify`.
 *
 * @throws JoseParseError if the token is not a Status List Token, `JoseVerificationError` if its
 *   signature, signer, algorithm or claims do not verify.
 * @throws StatusListError if the status list cannot be decompressed.
 * @throws StatusListEntryNotValidError if the status at `idx` is not `Valid`.
 */
export async function verifyStatusListJwt({
  jwt,
  uri,
  idx,
  ...options
}: VerifyStatusListJwtOptions): Promise<VerifyStatusListJwtResult> {
  const decoded = decodeStatusListJwt(typeof jwt === 'string' ? jwt : jwt.compact)

  const {
    verifyJwsCallback,
    signer,
    allowedSignerMethods,
    allowMultipleSignerMethods,
    allowDidKidIssuerMismatch,
    allowedAlgorithms,
    allowSymmetricAlgorithms,
    ...claimsOptions
  } = options

  // The signature is verified first, since the claims of a token whose signer has not been
  // established say nothing about anything.
  const { signer: verifiedSigner } = await verifyJwsSignature({
    jws: {
      protectedHeader: decoded.header,
      signingInput: decoded.signingInput,
      signature: decoded.signature,
      payload: decoded.payloadBytes,
      compact: decoded.compact,
    },
    jwtPayload: decoded.payload,
    verifyJwsCallback,
    signer,
    allowedSignerMethods,
    allowMultipleSignerMethods,
    allowDidKidIssuerMismatch,
    allowedAlgorithms,
    allowSymmetricAlgorithms,
    errorMessage: claimsOptions.errorMessage ?? 'Error during verification of the Status List Token.',
  })

  verifyStatusListJwtClaims(decoded.payload, { ...claimsOptions, uri })

  // Read, and so decompressed, only now that the token is known to be the issuer's
  const statusList = decoded.statusList

  if (idx !== undefined) {
    const status = statusList.getStatus(idx)
    if (status !== StatusType.Valid) {
      throw new StatusListEntryNotValidError(
        `Status for id '${idx}' is not Valid (${StatusType.Valid}), but is instead '${status}'`,
        { idx, status }
      )
    }
  }

  return {
    header: decoded.header,
    payload: decoded.payload,
    signer: verifiedSigner,
    compact: decoded.compact,
    statusList,
  }
}
