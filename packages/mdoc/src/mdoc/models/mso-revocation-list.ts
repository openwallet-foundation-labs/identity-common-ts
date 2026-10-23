import {
  CoseInvalidSignatureError,
  CoseX5ChainNotBoundError,
  getIntegrityProtectedX5Chain,
  RegisteredCwtClaimKey,
  SignatureAlgorithm,
} from '@owf/cose'
import { base64, base64url, decodeJwt, stringToBytes } from '@owf/identity-common'
import {
  fetchStatusList,
  getListFromStatusListJWT,
  SLException,
  type StatusList,
  StatusListCwt,
  type StatusListInfo,
  type StatusListJWTPayload,
  StatusType,
  verifyStatusListJwtClaims,
  verifyStatusListJwtHeader,
} from '@owf/token-status-list'
import type { MdocContext } from '../../context'
import {
  InvalidIdentifierListSignatureError,
  InvalidRevocationListError,
  InvalidSignatureError,
  type MdlError,
  NoPublicKeySetOnStatusListError,
  StatusListEntryNotValidError,
  TrustedRevocationCertificatesMustContainAtleastOneCertificateError,
  UnableToExtractX5ChainFromCwtError,
  UnableToExtractX5ChainFromIdentifierListError,
  UnableToExtractX5ChainFromJwtError,
  UnprotectedX5ChainNotBoundError,
} from '../errors'
import { IdentifierListCwt } from './identifier-list-cwt'
import type { IdentifierListInfo } from './identifier-list-info'

/**
 * Runs the claim and status checks `@owf/cose` and `@owf/token-status-list` own, translating the
 * errors they raise into the mdoc error hierarchy so that a caller of `IssuerAuth.verify` only ever
 * has to know `MdlError`.
 */
async function asMdlRevocationListError<T>(
  verification: () => Promise<T> | T,
  /** The error to report a failed signature as. */
  invalidSignatureError: new (message: string) => MdlError
): Promise<T> {
  try {
    return await verification()
  } catch (error) {
    if (error instanceof CoseInvalidSignatureError) throw new invalidSignatureError(error.message)
    if (error instanceof CoseX5ChainNotBoundError) throw new UnprotectedX5ChainNotBoundError(error.message)
    if (error instanceof SLException) throw new InvalidRevocationListError(error.message)
    throw error
  }
}

/**
 * The trust anchors a revocation list signer is validated against. Also checked before the list is
 * fetched, so that a verification that cannot succeed does not request the URI in the MSO.
 */
function assertTrustedCertificates({
  trustedCertificates,
}: {
  trustedCertificates?: Array<Uint8Array>
}): Array<Uint8Array> {
  if (!trustedCertificates || trustedCertificates.length === 0) {
    throw new TrustedRevocationCertificatesMustContainAtleastOneCertificateError(
      'Atleast one certificate is required to check the status of the mdoc. Make sure to supply them in the `trustedStatusCertificates` option'
    )
  }

  return trustedCertificates
}

/**
 * Establishes the signer of a revocation list: the certificate chain it carries, validated against
 * the mdoc trust anchors unless certificate chain validation is disabled, and the public key of its
 * leaf.
 *
 * § 12.3.6.3 requires the chain to travel in the protected header of the CWT: "The CWT shall
 * contain the x5chain in the protected header that contains the certificate or chain of
 * certificates used to verify the signature". A status list may instead carry it in the
 * unprotected header when a protected `x5t` binds its leaf, as RFC 9360 allows.
 */
async function verifyRevocationListSigner(
  {
    x5chain,
    algorithm,
    trustedCertificates,
    disableCertificateChainValidation,
    now,
  }: {
    x5chain: Array<Uint8Array>
    algorithm?: SignatureAlgorithm
    trustedCertificates?: Array<Uint8Array>
    disableCertificateChainValidation?: boolean
    now: Date
  },
  ctx: Pick<MdocContext, 'x509'>
) {
  let chain: Array<Uint8Array> | undefined
  if (!disableCertificateChainValidation) {
    ;({ chain } = await ctx.x509.verifyCertificateChain({
      trustedCertificates: assertTrustedCertificates({ trustedCertificates }),
      x5chain,
      now,
    }))
  }

  const key = await ctx.x509.getPublicKey({ certificate: x5chain[0], algorithm })
  if (!key) {
    throw new NoPublicKeySetOnStatusListError()
  }

  return { chain, key }
}

/**
 * The JWS algorithms a status list in JWT format may be signed with: ECDSA only, whose raw `r||s`
 * signature is the same in JWS and COSE, with the length of that signature (RFC 7518 § 3.4). `none`
 * and HMAC are refused, as an HMAC keyed with the public key of the certificate would be accepted
 * from anyone.
 */
const jwsSignatureAlgorithms = new Map<string, { algorithm: SignatureAlgorithm; signatureLength: number }>([
  ['ES256', { algorithm: SignatureAlgorithm.ES256, signatureLength: 64 }],
  ['ES384', { algorithm: SignatureAlgorithm.ES384, signatureLength: 96 }],
  ['ES512', { algorithm: SignatureAlgorithm.ES512, signatureLength: 132 }],
])

const isJsonObject = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value)

/**
 * Verify a status list in JWT format the way {@link verifyStatusListToken} verifies a CWT: the
 * signer from the `x5c` header, the signature with the `MdocContext` callbacks, then the header and
 * claims, with the same mandatory `exp`.
 */
async function verifyStatusListJwt(
  {
    jwt,
    uri,
    trustedCertificates,
    disableCertificateChainValidation,
    now,
    skewSeconds,
    checkFreshness,
  }: { jwt: string; uri: string; now: Date } & Omit<VerifyStatusListTokenOptions, 'statusListInfo' | 'now'>,
  ctx: Pick<MdocContext, 'x509' | 'cose'>
) {
  let header: Record<string, unknown>
  let payload: StatusListJWTPayload
  let signature: Uint8Array
  try {
    let encodedSignature: string
    ;({ header, payload, signature: encodedSignature } = decodeJwt<Record<string, unknown>, StatusListJWTPayload>(jwt))
    if (!isJsonObject(header) || !isJsonObject(payload)) throw new Error('The header and payload must be objects')
    signature = base64url.decode(encodedSignature)
  } catch {
    throw new InvalidRevocationListError(`The status list at ${uri} is not a valid JWT`)
  }

  // RFC 7515 § 4.1.11: a `crit` extension the recipient does not understand must be rejected, and
  // none is understood here.
  if (header.crit !== undefined) {
    throw new InvalidRevocationListError(`The status list at ${uri} has a crit header, which is not supported`)
  }

  const jwsAlgorithm = typeof header.alg === 'string' ? jwsSignatureAlgorithms.get(header.alg) : undefined
  if (jwsAlgorithm === undefined) {
    // The value is not echoed in full, as it comes from the list before its signature is verified.
    const signedWith = typeof header.alg === 'string' ? `unsupported alg '${header.alg.slice(0, 32)}'` : 'no valid alg'
    throw new InvalidRevocationListError(`The status list at ${uri} is signed with ${signedWith}`)
  }
  const { algorithm, signatureLength } = jwsAlgorithm

  const { x5c } = header
  if (!Array.isArray(x5c) || x5c.length === 0 || !x5c.every((cert) => typeof cert === 'string')) {
    throw new UnableToExtractX5ChainFromJwtError()
  }
  let x5chain: Array<Uint8Array>
  try {
    // RFC 7515 § 4.1.6: standard base64 DER, not base64url.
    x5chain = x5c.map((cert: string) => base64.decode(cert))
  } catch {
    throw new UnableToExtractX5ChainFromJwtError()
  }

  const { chain, key } = await verifyRevocationListSigner(
    {
      x5chain,
      algorithm,
      trustedCertificates,
      disableCertificateChainValidation,
      now,
    },
    ctx
  )

  // A DER-encoded signature, as some signers produce, is not a JWS signature and is rejected here
  // rather than left to the `sign1.verify` callback, which may throw on an unexpected length.
  if (signature.length !== signatureLength) {
    throw new InvalidSignatureError(
      `The signature of the status list at ${uri} is ${signature.length} bytes, not the ${signatureLength} bytes of a raw ${header.alg} signature`
    )
  }

  // NOTE: `sign1.verify` is used as a raw signature check over the JWS signing input, which it
  // does not parse, so the context needs no JWT callback.
  const isValid = await ctx.cose.sign1.verify({
    toBeVerified: stringToBytes(jwt.slice(0, jwt.lastIndexOf('.'))),
    signature,
    key,
    algorithm,
  })
  if (!isValid) {
    throw new InvalidSignatureError(`The signature of the status list at ${uri} is not valid`)
  }

  await asMdlRevocationListError(() => {
    verifyStatusListJwtHeader(header)
    verifyStatusListJwtClaims(payload, { uri, now, skewSeconds, checkFreshness, requireExpirationTime: true })
  }, InvalidSignatureError)

  let statusList: StatusList
  try {
    statusList = getListFromStatusListJWT(jwt)
  } catch {
    throw new InvalidRevocationListError(`The status list at ${uri} has no valid status_list claim`)
  }

  return { statusListJwt: { header, payload, statusList }, chain }
}

/**
 * The status at `idx` must be Valid, as § 12.3.6.1 allows "no other status besides 'revoked'".
 * Checked only once the list verified, so that a list that does not verify is never reported as a
 * status (Token Status List § 8.3), and the same way for a CWT and a JWT.
 */
function assertStatusIsValid(statusList: StatusList, { uri, idx }: { uri: string; idx: number }) {
  const status = statusList.getStatus(idx)
  if (status !== StatusType.Valid) {
    throw new StatusListEntryNotValidError(
      `Status for id '${idx}' is not Valid (${StatusType.Valid}), but is instead '${status}'`,
      { uri, idx, status }
    )
  }
}

export type VerifyStatusListTokenOptions = {
  statusListInfo: Pick<StatusListInfo, 'uri' | 'idx'>
  /**
   * Trust anchors for the certificate chain of the list signer. Required unless
   * `disableCertificateChainValidation` is set.
   */
  trustedCertificates?: Array<Uint8Array>
  /**
   * Verify the list with the key of the leaf of its x5chain, without validating the chain.
   */
  disableCertificateChainValidation?: boolean
  now?: Date
  skewSeconds?: number
  checkFreshness?: boolean
}

/** A status list served in JWT format, once verified. */
export type VerifiedStatusListJwt = {
  header: Record<string, unknown>
  payload: StatusListJWTPayload
  statusList: StatusList
}

export type VerifyStatusListTokenResult = {
  /** The verified list, when it was served in CWT format. */
  statusListCwt?: StatusListCwt
  /** The verified list, when it was served in JWT format instead. */
  statusListJwt?: VerifiedStatusListJwt
  /** The validated certificate chain of the list signer, leaf first. Not set without chain validation. */
  chain?: Array<Uint8Array>
}

/**
 * Fetch and verify the status list a `StatusListInfo` points at.
 *
 * `@owf/token-status-list` owns everything status-list-shaped — fetching and content-type
 * negotiation, the CWT structure, the claim checks and reading a status by index. What lives here
 * is what that library cannot know about: the mdoc trust anchors and the `MdocContext` crypto
 * callbacks used to establish the signer, and the two rules ISO/IEC 18013-5 § 12.3.6 layers on top
 * of the Token Status List defaults — a mandatory `exp` (§ 12.3.6.3), and `Valid` as the only
 * acceptable status, since § 12.3.6.1 allows "no other status besides 'revoked'".
 *
 * § 12.3.6.3 requires the list to be a Status List Token "in CWT format, since the IssuerAuth
 * structure is a CWT", so CWT is preferred. A list served as a JWT is still accepted as a fallback,
 * verified to the same rules; the JWS checks (ECDSA only, no `crit`, the `x5c` signer chain) live
 * in `verifyStatusListJwt`.
 *
 * The signer chain of a CWT is read from the protected header, as § 12.3.6.3 requires, or else from
 * the unprotected header when a protected `x5t` matches its leaf (RFC 9360).
 */
export async function verifyStatusListToken(
  {
    statusListInfo,
    trustedCertificates,
    disableCertificateChainValidation,
    now = new Date(),
    skewSeconds,
    checkFreshness,
  }: VerifyStatusListTokenOptions,
  ctx: Pick<MdocContext, 'fetch' | 'x509' | 'cose' | 'crypto'>
): Promise<VerifyStatusListTokenResult> {
  if (!disableCertificateChainValidation) assertTrustedCertificates({ trustedCertificates })

  const { uri, idx } = statusListInfo
  // CWT is preferred, so that an issuer that serves both returns the format § 12.3.6.3 requires. The
  // JWT is asked for with a lower quality value, and still accepted if a server returns it anyway.
  const token = await fetchStatusList({ uri, customFetcher: ctx.fetch, acceptedFormats: ['cwt', 'jwt'] })

  // NOTE: a JWT is NOT allowed by § 12.3.6.3, but some issuers serve the status list of an mdoc
  // as JWT only. So it is accepted as a fallback, with the same checks and status handling as a CWT.
  if (typeof token === 'string') {
    const { statusListJwt, chain } = await verifyStatusListJwt(
      { jwt: token, uri, trustedCertificates, disableCertificateChainValidation, now, skewSeconds, checkFreshness },
      ctx
    )
    assertStatusIsValid(statusListJwt.statusList, { uri, idx })

    return { statusListJwt, chain }
  }

  const statusListCwt = StatusListCwt.fromToken(token)

  // NOTE: an unprotected x5chain is NOT allowed by § 12.3.6.3, but RFC 9360 allows it when a
  // protected x5t binds the leaf. So it is accepted with that binding.
  const x5chain = await asMdlRevocationListError(
    () => getIntegrityProtectedX5Chain(statusListCwt, ctx.crypto),
    InvalidSignatureError
  )
  if (!x5chain) {
    throw new UnableToExtractX5ChainFromCwtError()
  }

  const { chain, key } = await verifyRevocationListSigner(
    {
      x5chain,
      algorithm: statusListCwt.algorithm as SignatureAlgorithm | undefined,
      trustedCertificates,
      disableCertificateChainValidation,
      now,
    },
    ctx
  )

  // Signature and claims first: the token is only the issuer's if it verifies, so there is nothing
  // to read from it before that.
  await asMdlRevocationListError(
    () =>
      statusListCwt.verify(
        {
          key,
          uri,
          now,
          skewSeconds,
          checkIssuedAt: checkFreshness,
          // § 12.3.6.3: "The exp claim shall be present." OPTIONAL in the Token Status List
          // specification, which is why it is required here rather than there.
          requiredClaims: [RegisteredCwtClaimKey.ExpirationTime],
        },
        { sign1: ctx.cose.sign1 }
      ),
    InvalidSignatureError
  )

  assertStatusIsValid(statusListCwt.payload.statusList, { uri, idx })

  return { statusListCwt, chain }
}

export type VerifyIdentifierListTokenOptions = {
  identifierListInfo: Pick<IdentifierListInfo, 'uri' | 'id'>
  /**
   * Trust anchors for the certificate chain of the list signer. Required unless
   * `disableCertificateChainValidation` is set.
   */
  trustedCertificates?: Array<Uint8Array>
  /**
   * Verify the list with the key of the leaf of its x5chain, without validating the chain.
   */
  disableCertificateChainValidation?: boolean
  now?: Date
  skewSeconds?: number
  checkFreshness?: boolean
}

export type VerifyIdentifierListTokenResult = {
  identifierListCwt: IdentifierListCwt
  /** The validated certificate chain of the list signer, leaf first. Not set without chain validation. */
  chain?: Array<Uint8Array>
}

/**
 * Fetch and verify the identifier list an `IdentifierListInfo` points at (§ 12.3.6.4):
 * certificate chain, signature, the claim checks § 12.3.6.1 makes binding on both revocation
 * mechanisms, and finally whether the MSO's own identifier appears in it — presence means revoked.
 *
 * The counterpart of {@link verifyStatusListToken}. Unlike a status list, the identifier list is an
 * ISO addition that the Token Status List specification does not describe, so `IdentifierListCwt`
 * lives in this package rather than in `@owf/token-status-list` — built on the same `Cwt`, so the
 * two are verified the same way.
 */
export async function verifyIdentifierListToken(
  {
    identifierListInfo,
    trustedCertificates,
    disableCertificateChainValidation,
    now = new Date(),
    skewSeconds,
    checkFreshness,
  }: VerifyIdentifierListTokenOptions,
  ctx: Pick<MdocContext, 'fetch' | 'x509' | 'cose'>
): Promise<VerifyIdentifierListTokenResult> {
  if (!disableCertificateChainValidation) assertTrustedCertificates({ trustedCertificates })

  const { uri, id } = identifierListInfo
  const identifierListCwt = await IdentifierListCwt.fetch(uri, ctx)

  const x5chain = identifierListCwt.x5chain
  if (!x5chain || x5chain.length === 0) {
    throw new UnableToExtractX5ChainFromIdentifierListError()
  }

  const { chain, key } = await verifyRevocationListSigner(
    {
      x5chain,
      algorithm: identifierListCwt.algorithm as SignatureAlgorithm | undefined,
      trustedCertificates,
      disableCertificateChainValidation,
      now,
    },
    ctx
  )

  await asMdlRevocationListError(
    () =>
      identifierListCwt.verify(
        { key, uri, id, now, skewSeconds, checkIssuedAt: checkFreshness },
        { sign1: ctx.cose.sign1 }
      ),
    InvalidIdentifierListSignatureError
  )

  return { identifierListCwt, chain }
}
