/**
 * Verification of registration certificates in either format of GEN-5.2.1-01.
 *
 * @see https://www.etsi.org/deliver/etsi_ts/119400_119499/119475/01.02.01_60/ts_119475v010201p.pdf
 */

import { CwtClaimVerificationError, CwtPayload } from '@owf/cose'
import { verifyJadesJwt } from '@owf/eudi-jades'
import { secondsToDate } from '@owf/identity-common'
import { JoseValidationError } from '@owf/jose'
import { decodeRegistrationCertificateCwt, verifyCwtSignature } from './cwt'
import { REGISTRATION_CERTIFICATE_JWS_ALGORITHMS } from './schemas'
import { decodeRegistrationCertificateJwt } from './signer'
import { verifyRegistrationCertificateStatus } from './status'
import type {
  DecodedRegistrationCertificateCwt,
  DecodedRegistrationCertificateJwt,
  RegistrationCertificatePayload,
  VerifyRegistrationCertificateCallbacks,
} from './types'
import { asValidationError, validateAccessCertificateSub, validationError } from './validator'

/** Options for {@link verifyRegistrationCertificate} */
export interface VerifyRegistrationCertificateOptions {
  /**
   * A compact JWS, the bytes of a CWT, or what a decode function of this package returned. That is verified as it is
   * passed, without decoding it again, so pass it unmodified.
   */
  registrationCertificate: string | Uint8Array | DecodedRegistrationCertificateJwt | DecodedRegistrationCertificateCwt
  /** Subject of the access certificate the registration certificate came with */
  accessCertificateSub: string
  /** Verify the signatures of the registration certificate and its status list, and whether their signer is trusted */
  callbacks: VerifyRegistrationCertificateCallbacks
  /** The time to verify at; defaults to now */
  now?: Date
  /** Clock tolerance for `exp` and `iat`, in seconds; defaults to 30 */
  skewSeconds?: number
  /** The maximum size in bytes the status list may inflate to; defaults to 16 MiB */
  maxStatusListDecompressedBytes?: number
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
  maxStatusListDecompressedBytes,
}: VerifyRegistrationCertificateOptions): Promise<
  DecodedRegistrationCertificateJwt | DecodedRegistrationCertificateCwt
> {
  let verified: DecodedRegistrationCertificateJwt | DecodedRegistrationCertificateCwt
  if (typeof registrationCertificate === 'string' || 'compact' in registrationCertificate) {
    const decoded = parseJwt(registrationCertificate, accessCertificateSub)
    verified = decoded
    try {
      // GEN-5.2.1-04: a JAdES B-B signature
      await verifyJadesJwt({
        // Spread, as TypeScript compares a `DecodeJwtResult` by its schemas instead of its header and payload
        jwt: { ...decoded },
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
    const decoded = parseCwt(registrationCertificate, accessCertificateSub)
    verified = decoded
    await verifyCwtSignature(decoded.registrationCertificateCwt, callbacks.verifyCose)
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
    await verifyRegistrationCertificateStatus({
      status,
      callbacks,
      now,
      skewSeconds,
      maxDecompressedBytes: maxStatusListDecompressedBytes,
    })
  } catch (error) {
    throw asValidationError(error, (error as Error).message.split('\n')[0], {
      code: 'invalid_status_list',
      path: ['payload', 'status'],
    })
  }

  return verified
}

/** What a decode function of this package returned is verified as it is passed, and a compact JWS is decoded */
function parseJwt(registrationCertificate: string | DecodedRegistrationCertificateJwt, accessCertificateSub: string) {
  if (typeof registrationCertificate === 'string') {
    return decodeRegistrationCertificateJwt(registrationCertificate, accessCertificateSub)
  }
  assertAccessCertificateSub(registrationCertificate.payload, accessCertificateSub)
  return registrationCertificate
}

/** The decoded CWT, as {@link parseJwt} */
function parseCwt(
  registrationCertificate: Uint8Array | DecodedRegistrationCertificateCwt,
  accessCertificateSub: string
) {
  if (registrationCertificate instanceof Uint8Array) {
    return decodeRegistrationCertificateCwt(registrationCertificate, accessCertificateSub)
  }
  assertAccessCertificateSub(registrationCertificate.payload, accessCertificateSub)
  return registrationCertificate
}

/** It may have been decoded without the subject of the access certificate, or with another one */
function assertAccessCertificateSub(payload: RegistrationCertificatePayload, accessCertificateSub: string) {
  const issue = validateAccessCertificateSub(payload, accessCertificateSub)
  if (issue) {
    throw validationError('Invalid registration certificate', { ...issue, path: ['payload', ...(issue.path ?? [])] })
  }
}

/** The claim issues of a JWT or CWT below `payload`, and any other failure as an `invalid_signature` issue */
function verificationError(error: unknown) {
  return asValidationError(error, 'Registration certificate does not verify', {
    code: 'invalid_signature',
    path: error instanceof JoseValidationError || error instanceof CwtClaimVerificationError ? ['payload'] : [],
  })
}
