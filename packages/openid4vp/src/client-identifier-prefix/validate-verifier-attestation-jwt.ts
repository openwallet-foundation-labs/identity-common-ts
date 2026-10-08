import { type CallbackContext, Oauth2Error } from '@openid4vc/oauth2'
import { decodeJwt, type Jwk, type JwsSigner, verifyJwt, zJwk, zJwtHeader } from '@owf/jose'
import z from 'zod'

export interface VerifyAttestationOptions {
  attestedJwt: string
  callbacks: Pick<CallbackContext, 'verifyJws'>
  expectedAttestationJwk: Jwk
}

export async function verifyAttestation(options: VerifyAttestationOptions) {
  const { callbacks, expectedAttestationJwk, attestedJwt } = options
  if (!expectedAttestationJwk.alg) {
    throw new Oauth2Error('Invalid verifier attestation missing required alg property')
  }
  const jwtSigner: JwsSigner = {
    method: 'jwk',
    alg: expectedAttestationJwk.alg,
    publicJwk: expectedAttestationJwk,
  }

  // The claims of the attested jwt are verified by the caller, so only the signature is checked here
  const { signer } = await verifyJwt({
    jwt: attestedJwt,
    signer: jwtSigner,
    verifyJwsCallback: callbacks.verifyJws,
    errorMessage: 'Invalid verifier attestation jwt. Signature verification failed.',
    checkExpirationTime: false,
    checkNotBefore: false,
    checkIssuedAt: false,
  })

  return { verified: true as const, signerJwk: signer.publicJwk }
}

export interface VerifyAttestationJwtOptions {
  attestationJwt: string
  clientId: string
  allowedSkewInSeconds?: number
  callbacks: Pick<CallbackContext, 'verifyJws'>
}
export async function verifyAttestationJwt(options: VerifyAttestationJwtOptions) {
  const errors = []

  const decodedJwt = decodeJwt({
    jwt: options.attestationJwt,
    headerSchema: z.object({ ...zJwtHeader.shape, typ: z.literal('verifier-attestation+jwt') }),
  })
  const { payload } = decodedJwt

  const { signer } = await verifyJwt({
    jwt: decodedJwt,
    verifyJwsCallback: options.callbacks.verifyJws,
    now: new Date(),
    expectedSubject: options.clientId,
    skewSeconds: options.allowedSkewInSeconds,
    requiredClaims: ['iss', 'sub', 'exp', 'cnf'],
  })

  // 4. Verify cnf claim structure
  if (payload.cnf) {
    if (!payload.cnf.jwk) {
      errors.push('cnf claim must contain a jwk')
    } else {
      // Verify JWK has required properties for a public key
      const jwk = payload.cnf.jwk
      if (!jwk.kty) {
        errors.push('JWK missing required kty property')
      }
    }
  }

  const isValid = errors.length === 0
  if (isValid) {
    return {
      isValid: true,
      signer,
      verifierPublicKey: zJwk.parse(payload.cnf?.jwk),
    } as const
  }

  return {
    isValid: false,
    errors: errors,
    verifierPublicKey: payload.cnf?.jwk,
  } as const
}
