import { type CallbackContext, isJwkInSet } from '@openid4vc/oauth2'
import { dateToSeconds, parseWithErrorHandling } from '@owf/identity-common'
import { decodeJwt, type JwsSigner, jwsHeaderFromSigner, signJwt, verifyJwt } from '@owf/jose'
import { Openid4vciError } from '../../../error/Openid4vciError'
import {
  type VerifyKeyAttestationJwtReturn,
  verifyKeyAttestationJwt,
  verifyKeyAttestationRequirements,
} from '../../../key-attestation/key-attestation'
import {
  type KeyAttestationsRequired,
  zKeyAttestationJwtHeader,
  zKeyAttestationJwtPayload,
} from '../../../key-attestation/z-key-attestation'
import {
  type CredentialRequestProofConfiguration,
  getSupportedProofType,
  verifyBindingMethodSupported,
  verifyProofSigningAlgSupported,
} from '../verify-proof-type-supported'
import {
  type CredentialRequestJwtProofTypeHeader,
  type CredentialRequestJwtProofTypePayload,
  zCredentialRequestJwtProofTypeHeader,
  zCredentialRequestJwtProofTypePayload,
} from './z-jwt-proof-type'

export interface CreateCredentialRequestJwtProofOptions {
  /**
   * Nonce to use in the jwt. Should be derived from the c_nonce
   */
  nonce?: string

  /**
   * The credential issuer identifier
   */
  credentialIssuer: string

  /**
   * The date when the token was issued. If not provided the current time will be used.
   */
  issuedAt?: Date

  /**
   * The client id of the wallet requesting the credential. Should not be included when using
   * the pre-authorized code flow
   */
  clientId?: string

  /**
   * Key attestation jwt that the proof should based on. In this case it is required that the `signer` uses
   * a key from the `attested_keys` in the key attestation jwt payload.
   */
  keyAttestationJwt?: string

  signer: JwsSigner
  callbacks: Pick<CallbackContext, 'signJws' | 'hash'>
}

export async function createCredentialRequestJwtProof(
  options: CreateCredentialRequestJwtProofOptions
): Promise<string> {
  const header = parseWithErrorHandling(zCredentialRequestJwtProofTypeHeader, {
    ...jwsHeaderFromSigner(options.signer),
    key_attestation: options.keyAttestationJwt,
    typ: 'openid4vci-proof+jwt',
  } satisfies CredentialRequestJwtProofTypeHeader)

  const payload = parseWithErrorHandling(zCredentialRequestJwtProofTypePayload, {
    nonce: options.nonce,
    aud: options.credentialIssuer,
    iat: dateToSeconds(options.issuedAt ?? new Date()),
    iss: options.clientId,
  } satisfies CredentialRequestJwtProofTypePayload)

  const { jwt, signerJwk } = await signJwt({
    header,
    payload,
    signer: options.signer,
    signJwsCallback: options.callbacks.signJws,
  })

  // Check the jwt is signed with an key from attested_keys in the key_attestation jwt
  if (options.keyAttestationJwt) {
    const decodedKeyAttestation = decodeJwt({
      jwt: options.keyAttestationJwt,
      headerSchema: zKeyAttestationJwtHeader,
      payloadSchema: zKeyAttestationJwtPayload,
    })

    const isSigedWithAttestedKey = await isJwkInSet({
      jwk: signerJwk,
      jwks: decodedKeyAttestation.payload.attested_keys,
      callbacks: options.callbacks,
    })

    if (!isSigedWithAttestedKey) {
      throw new Openid4vciError(
        `Credential request jwt proof is not signed with a key in the 'key_attestation' jwt payload 'attested_keys'`
      )
    }
  }

  return jwt
}

export interface VerifyCredentialRequestJwtProofOptions {
  /**
   * The proof jwt
   */
  jwt: string

  /**
   * Expected nonce. Should be a c_nonce previously shared with the wallet
   */
  expectedNonce?: string

  /**
   * Date at which the nonce will expire
   */
  nonceExpiresAt?: Date

  /**
   * The credential issuer identifier, will be matched against the `aud` claim.
   */
  credentialIssuer: string

  /**
   * The client id of the wallet requesting the credential, if available.
   */
  clientId?: string

  /**
   * Current time, if not provided a new date instance will be created
   */
  now?: Date

  /**
   * Allowed clock skew in seconds for the `exp`, `nbf` and `iat` checks of the proof and its `key_attestation`.
   *
   * @default 30
   */
  allowedSkewInSeconds?: number

  /**
   * The `key_attestations_required` value of the `jwt` proof type from the credential configuration in the
   * credential issuer metadata. If provided, the proof MUST contain a `key_attestation` that meets these
   * requirements.
   */
  keyAttestationsRequired?: KeyAttestationsRequired

  credentialConfiguration?: CredentialRequestProofConfiguration

  /**
   * Callbacks required for the jwt verification.
   *
   * Will be used for the jwt proof, and optionally a `key_attestation` in the jwt proof header.
   */
  callbacks: Pick<CallbackContext, 'verifyJws' | 'hash'>
}

const MAX_PROOF_AGE_SECONDS = 300

export async function verifyCredentialRequestJwtProof(options: VerifyCredentialRequestJwtProofOptions) {
  const decodedJwt = decodeJwt({
    jwt: options.jwt,
    headerSchema: zCredentialRequestJwtProofTypeHeader,
    payloadSchema: zCredentialRequestJwtProofTypePayload,
  })
  const { header, payload } = decodedJwt

  const supportedProofType = getSupportedProofType(options.credentialConfiguration, 'jwt')
  verifyProofSigningAlgSupported(supportedProofType, 'jwt', header.alg)
  const keyAttestationsRequired = options.keyAttestationsRequired ?? supportedProofType?.key_attestations_required

  const now = options.now?.getTime() ?? Date.now()
  if (options.nonceExpiresAt && now > options.nonceExpiresAt.getTime()) {
    throw new Openid4vciError('Nonce used for credential request proof expired')
  }

  const { signer } = await verifyJwt({
    jwt: decodedJwt,
    // The `iss` of a key proof is the client id rather than the did, so a `kid` that does not start
    // with it is not a mismatch. This is the one token type that is true for.
    allowDidKidIssuerMismatch: true,
    verifyJwsCallback: options.callbacks.verifyJws,
    errorMessage: 'Error verifying credential request proof jwt.',
    expectedNonce: options.expectedNonce,
    expectedAudience: options.credentialIssuer,
    expectedIssuer: options.clientId,
    // OpenID4VCI 1.0 Appendix F.4: the creation time of the proof must be within an acceptable window, which
    // limits the replay of a proof without a nonce
    maxAgeSeconds: MAX_PROOF_AGE_SECONDS,
    now: options.now,
    skewSeconds: options.allowedSkewInSeconds,
  })

  let keyAttestationResult: VerifyKeyAttestationJwtReturn | undefined
  // Check the jwt is signed with an key from attested_keys in the key_attestation jwt
  if (header.key_attestation) {
    keyAttestationResult = await verifyKeyAttestationJwt({
      callbacks: options.callbacks,
      keyAttestationJwt: header.key_attestation,
      use: 'proof_type.jwt',
      now: options.now,
      allowedSkewInSeconds: options.allowedSkewInSeconds,
      keyAttestationsRequired,
    })

    const isSignedWithAttestedKey = await isJwkInSet({
      jwk: signer.publicJwk,
      jwks: keyAttestationResult.payload.attested_keys,
      callbacks: options.callbacks,
    })

    if (!isSignedWithAttestedKey) {
      throw new Openid4vciError(
        `Credential request jwt proof is not signed with a key in the 'key_attestation' jwt payload 'attested_keys'`
      )
    }
  }

  // Throws if a key attestation is required but the proof does not contain one
  if (!keyAttestationResult) {
    verifyKeyAttestationRequirements({ keyAttestationsRequired })
  }

  verifyBindingMethodSupported(options.credentialConfiguration, signer)

  return {
    header,
    payload,
    signer,
    keyAttestation: keyAttestationResult,
  }
}
