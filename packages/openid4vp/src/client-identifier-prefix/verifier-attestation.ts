import { type CallbackContext, Oauth2ErrorCodes, Oauth2ServerErrorResponseError } from '@openid4vc/oauth2'
import { IdentityError, zNonEmptyString, zNumericDate, zTyp } from '@owf/identity-common'
import {
  type DecodeJwtResult,
  decodeJwt,
  JoseInvalidArgumentError,
  type JwsSignerWithJwk,
  verifyJwt,
  zJwtHeader,
  zJwtPayload,
  zPublicJwk,
} from '@owf/jose'
import z from 'zod'

/** The header of a Verifier Attestation JWT (OpenID4VP 1.0 Section 12) */
export const zVerifierAttestationJwtHeader = z
  .object({ ...zJwtHeader.shape, typ: zTyp('verifier-attestation+jwt') })
  .loose()

/** The payload of a Verifier Attestation JWT (OpenID4VP 1.0 Section 12) */
export const zVerifierAttestationJwtPayload = z
  .object({
    ...zJwtPayload.shape,
    iss: zNonEmptyString,
    sub: zNonEmptyString,
    exp: zNumericDate,
    cnf: z.object({ jwk: zPublicJwk }).loose(),
    redirect_uris: z.array(zNonEmptyString).optional(),
  })
  .loose()

export interface VerifyVerifierAttestationOptions {
  /** The `jwt` header parameter of the request object, which carries the Verifier Attestation JWT */
  verifierAttestationJwt: unknown

  /** The client identifier without the `verifier_attestation:` prefix, which the `sub` of the attestation must be */
  clientIdIdentifier: string

  /** The `redirect_uri` of the request, which must be one of the `redirect_uris` of the attestation when it has them */
  redirectUri?: string

  callbacks: Pick<CallbackContext, 'verifyJws'>

  /** Date to verify the `exp`, `nbf` and `iat` of the attestation against. Defaults to the current date. */
  now?: Date

  /**
   * Allowed clock skew in seconds for the `exp`, `nbf` and `iat` checks.
   *
   * @default 30
   */
  allowedSkewInSeconds?: number
}

export type VerifiedVerifierAttestation = DecodeJwtResult<
  typeof zVerifierAttestationJwtHeader,
  typeof zVerifierAttestationJwtPayload
> & { signer: JwsSignerWithJwk }

/**
 * Verify the Verifier Attestation JWT of a request that uses the `verifier_attestation` client identifier
 * prefix (OpenID4VP 1.0 Section 5.9.3 and Section 12). The request object must then be signed with the key
 * in its `cnf` claim.
 *
 * The `verifyJws` callback decides whether the wallet trusts the issuer (`iss`) of the attestation, as the
 * specification leaves how a wallet establishes that trust out of scope. Recognize the attestation with
 * `isJwtTyp(context.protectedHeader.typ, 'verifier-attestation+jwt')` of `@owf/identity-common`, as the `typ` is
 * accepted in any casing and with the `application/` prefix: a check for the exact value lets an attestation in
 * another form through as a JWT whose signer is not checked against a trusted issuer. Only verify an attestation
 * whose signer is a trusted issuer. A `jwk` in the header proves nothing about who issued it.
 *
 * When the attestation has `redirect_uris`, the request must have a `redirect_uri` that is one of them, as
 * Section 5.9.3 requires. A request with `response_mode` `direct_post` or over the DC API has no `redirect_uri`,
 * so it is rejected.
 *
 * @throws Oauth2ServerErrorResponseError with `invalid_request_object` when the attestation is missing, does not
 *   verify, or does not allow the client identifier or the `redirect_uri` of the request
 */
export async function verifyVerifierAttestation(
  options: VerifyVerifierAttestationOptions
): Promise<VerifiedVerifierAttestation> {
  if (typeof options.verifierAttestationJwt !== 'string') {
    throw new Oauth2ServerErrorResponseError({
      error: Oauth2ErrorCodes.InvalidRequestObject,
      error_description: `The client identifier prefix 'verifier_attestation' requires a Verifier Attestation JWT in the 'jwt' header of the request object.`,
    })
  }

  let verifierAttestation: VerifiedVerifierAttestation
  try {
    const jwt = decodeJwt({
      jwt: options.verifierAttestationJwt,
      headerSchema: zVerifierAttestationJwtHeader,
      payloadSchema: zVerifierAttestationJwtPayload,
    })
    const { signer } = await verifyJwt({
      jwt,
      verifyJwsCallback: options.callbacks.verifyJws,
      expectedSubject: options.clientIdIdentifier,
      now: options.now,
      skewSeconds: options.allowedSkewInSeconds,
      errorMessage: 'Verification of the verifier attestation failed',
    })
    verifierAttestation = { ...jwt, signer }
  } catch (error) {
    // An invalid option, such as a `now` that is not a date, is a mistake of the caller, not of the attestation
    if (!(error instanceof IdentityError) || error instanceof JoseInvalidArgumentError) throw error

    throw new Oauth2ServerErrorResponseError(
      {
        error: Oauth2ErrorCodes.InvalidRequestObject,
        error_description: 'The verifier attestation of the request object could not be verified.',
      },
      { cause: error, internalMessage: error.message }
    )
  }

  const { redirect_uris } = verifierAttestation.payload
  if (redirect_uris && (options.redirectUri === undefined || !redirect_uris.includes(options.redirectUri))) {
    throw new Oauth2ServerErrorResponseError({
      error: Oauth2ErrorCodes.InvalidRequestObject,
      error_description: `The 'redirect_uri' of the request is not one of the 'redirect_uris' of the verifier attestation.`,
    })
  }

  return verifierAttestation
}
