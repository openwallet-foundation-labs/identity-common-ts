import {
  type CallbackContext,
  decodeJwt,
  type Jwk,
  type JwtSigner,
  jwtHeaderFromJwtSigner,
  jwtSignerFromJwt,
  verifyJwt,
} from '@openid4vc/oauth2'
import { dateToSeconds, parseWithErrorHandling, type StringWithAutoCompletion } from '@openid4vc/utils'
import { Openid4vciError } from '../error/Openid4vciError'
import {
  type Iso18045,
  type KeyAttestationJwtHeader,
  type KeyAttestationJwtPayload,
  type KeyAttestationJwtUse,
  type KeyAttestationsRequired,
  zKeyAttestationJwtHeader,
  zKeyAttestationJwtPayloadForUse,
} from './z-key-attestation'

export interface CreateKeyAttestationJwtOptions {
  /**
   * Nonce to use in the key attestation.
   *
   * MUST be present if the attestation is used with the attestation proof
   */
  nonce?: string

  /**
   * The date when the key attestation was issued. If not provided the current time will be used.
   */
  issuedAt?: Date

  /**
   * The date when the key attestation will expire.
   *
   * MUST be present if the attestation is used with the JWT proof
   */
  expiresAt?: Date

  /**
   * The keys that the attestation jwt attests.
   */
  attestedKeys: Jwk[]

  /**
   * Optional attack potential resistance of attested keys and key storage
   */
  keyStorage?: StringWithAutoCompletion<Iso18045>[]

  /**
   * Optional attack potential resistance of user authentication methods
   */
  userAuthentication?: StringWithAutoCompletion<Iso18045>[]

  /**
   * Optional url linking to the certification of the key storage component.
   */
  certification?: string

  /**
   * The intended use of the key attestation. Based on this additional validation
   * is performed.
   *
   * - `proof_type.jwt` -> `exp` MUST be set
   * - `proof_type.attestation` -> `nonce` MUST be set
   */
  use?: KeyAttestationJwtUse

  /**
   * Signer of the key attestation jwt
   */
  signer: JwtSigner

  /**
   * Callbacks used for creating the key attestation jwt
   */
  callbacks: Pick<CallbackContext, 'signJwt'>

  /**
   * Additional payload to include in the key attestation jwt payload. Will be applied after
   * any default claims that are included, so add claims with caution.
   */
  additionalPayload?: Record<string, unknown>
}

export async function createKeyAttestationJwt(options: CreateKeyAttestationJwtOptions): Promise<string> {
  const header = parseWithErrorHandling(zKeyAttestationJwtHeader, {
    ...jwtHeaderFromJwtSigner(options.signer),
    typ: 'key-attestation+jwt',
  } satisfies KeyAttestationJwtHeader)

  const payload = parseWithErrorHandling(zKeyAttestationJwtPayloadForUse(options.use), {
    iat: dateToSeconds(options.issuedAt),
    exp: options.expiresAt ? dateToSeconds(options.expiresAt) : undefined,
    nonce: options.nonce,
    attested_keys: options.attestedKeys,
    user_authentication: options.userAuthentication,
    key_storage: options.keyStorage,
    certification: options.certification,
    ...options.additionalPayload,
  } satisfies KeyAttestationJwtPayload)

  const { jwt } = await options.callbacks.signJwt(options.signer, { header, payload })
  return jwt
}

export interface ParseKeyAttestationJwtOptions {
  /**
   * The compact key attestation jwt
   */
  keyAttestationJwt: string

  /**
   * The intended use of the key attestation. Based on this additional validation
   * is performed.
   *
   * - `proof_type.jwt` -> `exp` MUST be set
   * - `proof_type.attestation` -> `nonce` MUST be set
   */
  use?: KeyAttestationJwtUse
}

export function parseKeyAttestationJwt({ keyAttestationJwt, use }: ParseKeyAttestationJwtOptions) {
  return decodeJwt({
    jwt: keyAttestationJwt,
    headerSchema: zKeyAttestationJwtHeader,
    payloadSchema: zKeyAttestationJwtPayloadForUse(use),
  })
}

export interface VerifyKeyAttestationJwtOptions {
  /**
   * The compact key attestation jwt
   */
  keyAttestationJwt: string

  /**
   * Expected nonce. If the key attestation is used directly as proof this should be provided.
   */
  expectedNonce?: string

  /**
   * Date at which the nonce will expire
   */
  nonceExpiresAt?: Date

  /**
   * The intended use of the key attestation. Based on this additional validation
   * is performed.
   *
   * - `proof_type.jwt` -> `exp` MUST be set
   * - `proof_type.attestation` -> `nonce` MUST be set
   */
  use?: KeyAttestationJwtUse

  /**
   * Current time, if not provided a new date instance will be created
   */
  now?: Date

  /**
   * The `key_attestations_required` value of the proof type from the credential configuration in the
   * credential issuer metadata. If provided, the key attestation is verified against these requirements.
   */
  keyAttestationsRequired?: KeyAttestationsRequired

  /**
   * Callbacks required for the key attestation jwt verification
   */
  callbacks: Pick<CallbackContext, 'verifyJwt'>
}

export type VerifyKeyAttestationJwtReturn = Awaited<ReturnType<typeof verifyKeyAttestationJwt>>
export async function verifyKeyAttestationJwt(options: VerifyKeyAttestationJwtOptions) {
  const { header, payload } = parseKeyAttestationJwt({ keyAttestationJwt: options.keyAttestationJwt, use: options.use })

  // TODO: if you use stateless nonce, it doesn't make sense to verify the nonce here
  // We should just return the nonce after verification so it can be checked (or actually, it should be checked upfront)
  const now = options.now?.getTime() ?? Date.now()
  if (options.nonceExpiresAt && now > options.nonceExpiresAt.getTime()) {
    throw new Openid4vciError('Nonce used for key attestation jwt expired')
  }

  const { signer } = await verifyJwt({
    compact: options.keyAttestationJwt,
    header,
    payload,
    signer: jwtSignerFromJwt({ header, payload }),
    verifyJwtCallback: options.callbacks.verifyJwt,
    errorMessage: 'Error verifying key attestation jwt',
    expectedNonce: options.expectedNonce,
    now: options.now,
  })

  verifyKeyAttestationRequirements({
    keyAttestation: payload,
    keyAttestationsRequired: options.keyAttestationsRequired,
  })

  return {
    header,
    payload,
    signer,
  }
}

export interface VerifyKeyAttestationRequirementsOptions {
  /**
   * The payload of the (verified) key attestation jwt that was provided in the credential request.
   * Can be left `undefined` if no key attestation was provided.
   */
  keyAttestation?: Pick<KeyAttestationJwtPayload, 'key_storage' | 'user_authentication'>

  /**
   * The `key_attestations_required` value of the proof type from the credential configuration in the
   * credential issuer metadata. If `undefined` the credential issuer does not require a key attestation.
   */
  keyAttestationsRequired?: KeyAttestationsRequired
}

/**
 * Verify that a key attestation meets the requirements from the credential issuer metadata.
 *
 * - If `keyAttestationsRequired` is not defined, no key attestation is required
 * - If it is defined, a key attestation MUST be provided
 * - For `key_storage` and `user_authentication`, if the credential issuer defines accepted values the
 *   key attestation MUST contain at least one of these values.
 *
 * @throws {Openid4vciError} if the key attestation does not meet the requirements
 */
export function verifyKeyAttestationRequirements(options: VerifyKeyAttestationRequirementsOptions) {
  const { keyAttestation, keyAttestationsRequired } = options
  if (!keyAttestationsRequired) return

  if (!keyAttestation) {
    throw new Openid4vciError(
      'A key attestation is required by the credential issuer, but no key attestation was provided'
    )
  }

  for (const claim of ['key_storage', 'user_authentication'] as const) {
    const acceptedValues = keyAttestationsRequired[claim]
    if (!acceptedValues) continue

    const attestedValues = keyAttestation[claim] ?? []
    if (!attestedValues.some((value) => acceptedValues.includes(value))) {
      throw new Openid4vciError(
        `Key attestation '${claim}' ${
          attestedValues.length > 0 ? `values '${attestedValues.join("', '")}' do` : 'is not defined and does'
        } not match any of the values accepted by the credential issuer: '${acceptedValues.join("', '")}'`
      )
    }
  }
}
