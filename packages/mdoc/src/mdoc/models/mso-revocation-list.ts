import {
  CoseInvalidSignatureError,
  CoseX5ChainNotBoundError,
  getIntegrityProtectedX5Chain,
  RegisteredCwtClaimKey,
  SignatureAlgorithm,
} from '@owf/cose'
import { base64, base64url } from '@owf/identity-common'
import {
  fetchStatusList,
  JoseError,
  JoseSignatureVerificationError,
  JoseValidationError,
  type StatusList,
  StatusListCwt,
  StatusListError,
  type StatusListInfo,
  type StatusListJwtPayload,
  StatusListValidationError,
  StatusType,
  type VerifyStatusListJwtOptions,
  verifyStatusListJwt as verifyTokenStatusListJwt,
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
    // The cause is what the verification callback threw, already an mdoc error
    if (error instanceof JoseSignatureVerificationError) throw error.cause ?? new invalidSignatureError(error.message)
    if (
      error instanceof StatusListError ||
      error instanceof StatusListValidationError ||
      error instanceof JoseError ||
      error instanceof JoseValidationError
    ) {
      throw new InvalidRevocationListError(error.message)
    }
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
type JwsSignatureAlgorithm = { algorithm: SignatureAlgorithm; signatureLength: number }
const jwsSignatureAlgorithms = new Map<string, JwsSignatureAlgorithm>([
  ['ES256', { algorithm: SignatureAlgorithm.ES256, signatureLength: 64 }],
  ['ES384', { algorithm: SignatureAlgorithm.ES384, signatureLength: 96 }],
  ['ES512', { algorithm: SignatureAlgorithm.ES512, signatureLength: 132 }],
])

/**
 * Checks the status at `idx`, only once the list verified, so that a list that does not verify is never
 * reported as a status (Token Status List § 8.3). § 12.3.6.1 accepts no status but Valid.
 */
async function assertStatusValid(statusList: StatusList, uri: string, idx: number) {
  const status = await asMdlRevocationListError(() => statusList.getStatus(idx), InvalidSignatureError)
  if (status !== StatusType.Valid) {
    throw new StatusListEntryNotValidError(
      `Status for id '${idx}' is not Valid (${StatusType.Valid}), but is instead '${status}'`,
      { uri, idx, status }
    )
  }
}

/**
 * Verify a status list in JWT format to the same rules as a CWT, with `verifyStatusListJwt` of
 * `@owf/token-status-list` and a callback that validates the `x5c` chain and checks the signature
 * with the `MdocContext`.
 */
async function verifyStatusListJwt(
  {
    jwt,
    uri,
    idx,
    trustedCertificates,
    disableCertificateChainValidation,
    now,
    skewSeconds,
    checkFreshness,
    maxDecompressedBytes,
  }: { jwt: string; uri: string; idx: number; now: Date } & Omit<
    VerifyStatusListTokenOptions,
    'statusListInfo' | 'now'
  >,
  ctx: Pick<MdocContext, 'x509' | 'cose'>
) {
  let chain: Array<Uint8Array> | undefined
  const verifyJwsCallback: VerifyStatusListJwtOptions['verifyJwsCallback'] = async (
    signer,
    { signingInputBytes, signature }
  ) => {
    if (signer.method !== 'x5c') throw new UnableToExtractX5ChainFromJwtError()
    // Set, as `allowedAlgorithms` only has the keys of the map
    const { algorithm, signatureLength } = jwsSignatureAlgorithms.get(signer.alg) as JwsSignatureAlgorithm

    const signerKey = await verifyRevocationListSigner(
      {
        // RFC 7515 § 4.1.6: standard base64 DER, not base64url.
        x5chain: signer.x5c.map((cert) => base64.decode(cert)),
        algorithm,
        trustedCertificates,
        disableCertificateChainValidation,
        now,
      },
      ctx
    )
    chain = signerKey.chain

    // A DER-encoded signature, as some signers produce, is not a JWS signature and is rejected here
    // rather than left to the `sign1.verify` callback, which may throw on an unexpected length.
    const signatureBytes = base64url.decode(signature)
    if (signatureBytes.length !== signatureLength) {
      throw new InvalidSignatureError(
        `The signature of the status list at ${uri} is ${signatureBytes.length} bytes, not the ${signatureLength} bytes of a raw ${signer.alg} signature`
      )
    }

    const verified = await ctx.cose.sign1.verify({
      toBeVerified: signingInputBytes,
      signature: signatureBytes,
      key: signerKey.key,
      algorithm,
    })
    if (!verified) throw new InvalidSignatureError(`The signature of the status list at ${uri} is not valid`)
    return { verified: true, signerJwk: signerKey.key.jwk as { kty: string } }
  }

  const { header, payload, statusList } = await asMdlRevocationListError(
    () =>
      verifyTokenStatusListJwt({
        jwt,
        uri,
        now,
        skewSeconds,
        checkIssuedAt: checkFreshness,
        // § 12.3.6.3: "The exp claim shall be present."
        requiredClaims: ['exp'],
        allowedAlgorithms: [...jwsSignatureAlgorithms.keys()],
        verifyJwsCallback,
        maxDecompressedBytes,
      }),
    InvalidSignatureError
  )

  await assertStatusValid(statusList, uri, idx)

  return { statusListJwt: { header, payload, statusList }, chain }
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
  /** The maximum size in bytes the status list may inflate to, 16 MiB by default. */
  maxDecompressedBytes?: number
  /** The maximum size in bytes of the response that serves the status list, 16 MiB by default. */
  maxResponseBytes?: number
}

/** A status list served in JWT format, once verified. */
export type VerifiedStatusListJwt = {
  header: Record<string, unknown>
  payload: StatusListJwtPayload
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
    maxDecompressedBytes,
    maxResponseBytes,
  }: VerifyStatusListTokenOptions,
  ctx: Pick<MdocContext, 'fetch' | 'x509' | 'cose' | 'crypto'>
): Promise<VerifyStatusListTokenResult> {
  if (!disableCertificateChainValidation) assertTrustedCertificates({ trustedCertificates })

  const { uri, idx } = statusListInfo
  // CWT is preferred, so that an issuer that serves both returns the format § 12.3.6.3 requires. The
  // JWT is asked for with a lower quality value, and still accepted if a server returns it anyway.
  const token = await fetchStatusList({
    uri,
    customFetcher: (input, init) => ctx.fetch(input, init, { type: 'statusList' }),
    acceptedFormats: ['cwt', 'jwt'],
    maxResponseBytes,
  })

  // NOTE: a JWT is NOT allowed by § 12.3.6.3, but some issuers serve the status list of an mdoc
  // as JWT only. So it is accepted as a fallback, with the same checks and status handling as a CWT.
  if (typeof token === 'string') {
    const { statusListJwt, chain } = await verifyStatusListJwt(
      {
        jwt: token,
        uri,
        idx,
        trustedCertificates,
        disableCertificateChainValidation,
        now,
        skewSeconds,
        checkFreshness,
        maxDecompressedBytes,
      },
      ctx
    )

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

  const statusList = await asMdlRevocationListError(
    () => statusListCwt.payload.getStatusList({ maxDecompressedBytes }),
    InvalidSignatureError
  )
  await assertStatusValid(statusList, uri, idx)

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
  /** The maximum size in bytes of the response that serves the identifier list, 16 MiB by default. */
  maxResponseBytes?: number
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
    maxResponseBytes,
  }: VerifyIdentifierListTokenOptions,
  ctx: Pick<MdocContext, 'fetch' | 'x509' | 'cose'>
): Promise<VerifyIdentifierListTokenResult> {
  if (!disableCertificateChainValidation) assertTrustedCertificates({ trustedCertificates })

  const { uri, id } = identifierListInfo
  const identifierListCwt = await IdentifierListCwt.fetch(uri, ctx, { maxResponseBytes })

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
