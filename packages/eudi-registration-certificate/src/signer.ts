/**
 * Registration Certificate Signer
 *
 * Functions for creating and signing ETSI TS 119 475 Wallet-Relying Party Registration Certificates.
 *
 * GEN-5.2.1-04 requires the JWT to carry a JAdES signature with the B-B profile of
 * ETSI TS 119 182-1, so signing, decoding and verification go through `@owf/eudi-jades`.
 *
 * @see https://www.etsi.org/deliver/etsi_ts/119400_119499/119475/01.02.01_60/ts_119475v010201p.pdf
 */

import { pemToDer } from '@owf/crypto'
import { decodeJades, signJades } from '@owf/eudi-jades'
import { decodeJwt } from '@owf/jose'
import { REGISTRATION_CERTIFICATE_DIALECTS, toRegistrationCertificateDialect } from './dialect'
import type {
  RegistrationCertificateJwtHeader,
  RegistrationCertificatePayload,
  SignedRegistrationCertificateJwt,
  SignJwtOptions,
} from './types'
import {
  assertValidRegistrationCertificate,
  assertValidRegistrationCertificatePayload,
  asValidationError,
  parseRegistrationCertificatePayload,
  validationError,
} from './validator'

// ============================================================================
// JWT Signing
// ============================================================================

/**
 * Sign a registration certificate payload into a JAdES B-B signed JWT
 *
 * @param options - Signing options including payload, algorithm, certificates, and the signing callback
 * @returns Signed registration certificate with JWS string and decoded parts
 * @throws RegistrationCertificateValidationError if the payload is not valid or `certificates` is empty
 */
export async function signRegistrationCertificateJwt(
  options: SignJwtOptions
): Promise<SignedRegistrationCertificateJwt> {
  const {
    payload,
    accessCertificateSub,
    algorithm = 'ES256',
    certificates,
    keyId,
    signJwsCallback,
    signingTime,
    dialect = REGISTRATION_CERTIFICATE_DIALECTS.CURRENT,
  } = options

  assertValidRegistrationCertificatePayload(payload, accessCertificateSub)

  if (certificates.length === 0) {
    throw validationError('Unable to sign the registration certificate', {
      code: 'missing_value',
      path: ['certificates'],
      message: 'At least one certificate is required for the x5c header',
      context: { expected: 'certificate' },
    })
  }

  const { jws, protectedHeader } = await signJades({
    protectedHeader: { typ: 'rc-wrp+jwt', ...(keyId && { kid: keyId }) },
    payload: toRegistrationCertificateDialect(payload, dialect) as Record<string, unknown>,
    signingTime: typeof signingTime === 'string' ? new Date(signingTime) : signingTime,
    signer: { method: 'x5c', alg: algorithm, x5c: certificates.map((certificate) => pemToDer(certificate)) },
    signJwsCallback,
  })

  return {
    jws,
    header: protectedHeader as RegistrationCertificateJwtHeader,
    payload,
  }
}

// ============================================================================
// JWT Decoding
// ============================================================================

/**
 * Decode a signed registration certificate JWT (without cryptographic verification)
 *
 * @param jws - The compact JWS string
 * @returns Decoded registration certificate with header and payload
 * @throws RegistrationCertificateValidationError with the issues of the JAdES B-B signature (GEN-5.2.1-04), and of the
 *   header and the payload, whose paths start with `header` or `payload`
 */
export function decodeRegistrationCertificateJwt(
  jws: string,
  accessCertificateSub: string
): SignedRegistrationCertificateJwt {
  let decoded: ReturnType<typeof decodeJwt>
  try {
    // GEN-5.2.1-04
    decodeJades({ jws })
    decoded = decodeJwt({ jwt: jws })
  } catch (error) {
    throw asValidationError(error, 'Registration certificate is not a JAdES B-B signed JWT (GEN-5.2.1-04)', {
      code: 'invalid_format',
      context: { format: 'JWT' },
    })
  }

  assertValidRegistrationCertificate(decoded.header, decoded.payload, accessCertificateSub)

  return {
    jws,
    header: decoded.header as RegistrationCertificateJwtHeader,
    payload: parseRegistrationCertificatePayload(decoded.payload, accessCertificateSub),
  }
}

/**
 * Parse a registration certificate JWT without validation (for inspection purposes)
 *
 * @param jws - The compact JWS string
 * @returns Decoded parts without validation
 * @throws RegistrationCertificateValidationError if it is not a JWT
 */
export function parseRegistrationCertificateJwt(jws: string): { header: unknown; payload: unknown; signature: string } {
  try {
    const { header, payload, signature } = decodeJwt({ jwt: jws })
    return { header, payload, signature }
  } catch (error) {
    throw asValidationError(error, 'Invalid registration certificate JWT', {
      code: 'invalid_format',
      context: { format: 'JWT' },
    })
  }
}

// ============================================================================
// Registration Certificate Creation Helpers
// ============================================================================

/**
 * Create a registration certificate with automatic timestamp
 *
 * @param payload - Partial payload (iat will be set automatically if not provided)
 * @returns Complete payload with timestamp
 */
export function createRegistrationCertificatePayload(
  payload: RegistrationCertificatePayload,
  accessCertificateSub: string
): RegistrationCertificatePayload {
  assertValidRegistrationCertificatePayload(payload, accessCertificateSub)

  return payload
}
