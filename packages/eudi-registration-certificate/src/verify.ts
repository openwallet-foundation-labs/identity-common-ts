/**
 * Verification of registration certificates in either format of GEN-5.2.1-01.
 *
 * @see https://www.etsi.org/deliver/etsi_ts/119400_119499/119475/01.02.01_60/ts_119475v010201p.pdf
 */

import { CwtClaimVerificationError, CwtPayload } from '@owf/cose'
import { verifyJadesJwt } from '@owf/eudi-jades'
import { secondsToDate } from '@owf/identity-common'
import { JoseValidationError } from '@owf/jose'
import { parseRegistrationCertificateCwt, verifyCwtSignature } from './cwt'
import { REGISTRATION_CERTIFICATE_JWS_ALGORITHMS } from './schemas'
import { decodeRegistrationCertificateJwt } from './signer'
import { verifyRegistrationCertificateStatus } from './status'
import type {
  SignedRegistrationCertificateCwt,
  SignedRegistrationCertificateJwt,
  VerifyRegistrationCertificateCallbacks,
} from './types'
import { asValidationError, validationError } from './validator'

/** Options for {@link verifyRegistrationCertificate} */
export interface VerifyRegistrationCertificateOptions {
  /** A compact JWS, the bytes of a CWT, or what a decode function of this package returned */
  registrationCertificate: string | Uint8Array | SignedRegistrationCertificateJwt | SignedRegistrationCertificateCwt
  /** Subject of the access certificate the registration certificate came with */
  accessCertificateSub: string
  /** Verify the signatures of the registration certificate and its status list, and whether their signer is trusted */
  callbacks: VerifyRegistrationCertificateCallbacks
  /** The time to verify at; defaults to now */
  now?: Date
  /** Clock tolerance for `exp` and `iat`, in seconds; defaults to 30 */
  skewSeconds?: number
}

/**
 * Verify a registration certificate, JWT or CWT: its header and payload (clause 5.2), its signature and the trust in its
 * signer through the callbacks, `iat` and `exp` against `now`, and its status in the status list it references (clause
 * 6.2.6). A registration certificate without `status` is rejected, as REV-6.2.6.2-03 has every one reference its status.
 *
 * @returns The verified registration certificate
 * @throws RegistrationCertificateValidationError with the issues, e.g. `invalid_signature`, `expired` or `revoked`. Their
 *   paths start with `header` or `payload`.
 */
export async function verifyRegistrationCertificate({
  registrationCertificate,
  accessCertificateSub,
  callbacks,
  now,
  skewSeconds,
}: VerifyRegistrationCertificateOptions): Promise<SignedRegistrationCertificateJwt | SignedRegistrationCertificateCwt> {
  const serialized =
    typeof registrationCertificate === 'string' || registrationCertificate instanceof Uint8Array
      ? registrationCertificate
      : 'jws' in registrationCertificate
        ? registrationCertificate.jws
        : registrationCertificate.cwt

  let verified: SignedRegistrationCertificateJwt | SignedRegistrationCertificateCwt
  if (typeof serialized === 'string') {
    verified = decodeRegistrationCertificateJwt(serialized, accessCertificateSub)
    try {
      // GEN-5.2.1-04: a JAdES B-B signature
      await verifyJadesJwt({
        jwt: serialized,
        verifyJwsCallback: callbacks.verifyJws,
        // Table 5: the chain is in `x5c`
        allowedSignerMethods: ['x5c'],
        allowedAlgorithms: REGISTRATION_CERTIFICATE_JWS_ALGORITHMS,
        now,
        skewSeconds,
      })
    } catch (error) {
      throw verificationError(error)
    }
  } else {
    const { registrationCertificateCwt, ...decoded } = parseRegistrationCertificateCwt(serialized, accessCertificateSub)
    verified = decoded
    await verifyCwtSignature(registrationCertificateCwt, callbacks.verifyCose)
    const { iat, exp } = decoded.payload
    try {
      // The claims as they are after decoding, as `iat` and `exp` may be under their JSON name
      CwtPayload.create({
        issuedAt: secondsToDate(iat),
        expirationTime: exp === undefined ? undefined : secondsToDate(exp),
      }).verifyClaims({ now, skewSeconds })
    } catch (error) {
      throw verificationError(error)
    }
  }

  const { status } = verified.payload
  if (!status) {
    throw validationError('Invalid registration certificate', {
      code: 'missing_value',
      path: ['payload', 'status'],
      message: 'Registration certificate has no status',
      requirement: 'REV-6.2.6.2-03',
      context: { expected: 'object' },
    })
  }
  try {
    await verifyRegistrationCertificateStatus({ status, callbacks, now, skewSeconds })
  } catch (error) {
    throw asValidationError(error, (error as Error).message.split('\n')[0], {
      code: 'invalid_status_list',
      path: ['payload', 'status'],
    })
  }

  return verified
}

/** The claim issues of a JWT or CWT below `payload`, and any other failure as an `invalid_signature` issue */
function verificationError(error: unknown) {
  return asValidationError(error, 'Registration certificate does not verify', {
    code: 'invalid_signature',
    path: error instanceof JoseValidationError || error instanceof CwtClaimVerificationError ? ['payload'] : [],
  })
}
