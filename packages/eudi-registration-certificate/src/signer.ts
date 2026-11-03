/**
 * Registration Certificate Signer
 *
 * Functions for creating and signing ETSI TS 119 475 Wallet-Relying Party Registration Certificates.
 *
 * GEN-5.2.1-04 requires the JWT to carry a JAdES signature with the B-B profile of
 * ETSI TS 119 182-1, so signing and decoding go through `@owf/eudi-jades`.
 *
 * @see https://www.etsi.org/deliver/etsi_ts/119400_119499/119475/01.02.01_60/ts_119475v010201p.pdf
 */

import { pemToDer } from '@owf/crypto'
import { decode, JadesProfile, Token, validateProfile } from '@owf/eudi-jades'
import { isJwtTyp } from '@owf/identity-common'
import { REGISTRATION_CERTIFICATE_DIALECTS, toRegistrationCertificateDialect } from './dialect'
import { RegistrationCertificateError } from './registration-certificate-error'
import type {
  RegistrationCertificateJwtHeader,
  RegistrationCertificatePayload,
  SignedRegistrationCertificate,
  SignOptions,
} from './types'
import { assertValidRegistrationCertificatePayload, parseRegistrationCertificatePayload } from './validator'

// ============================================================================
// JWT Signing
// ============================================================================

/**
 * Sign a registration certificate payload into a JAdES B-B signed JWT
 *
 * @param options - Signing options including payload, algorithm, certificates, and signer
 * @returns Signed registration certificate with JWS string and decoded parts
 */
export async function signRegistrationCertificate(options: SignOptions): Promise<SignedRegistrationCertificate> {
  const {
    payload,
    accessCertificateSub,
    algorithm = 'ES256',
    certificates,
    keyId,
    signer,
    signingTime,
    dialect = REGISTRATION_CERTIFICATE_DIALECTS.CURRENT,
  } = options

  // Validate payload
  assertValidRegistrationCertificatePayload(payload, accessCertificateSub)

  if (!certificates || certificates.length === 0) {
    throw new RegistrationCertificateError('At least one certificate is required for x5c header')
  }

  // Extract base64 content from PEM certificates
  const x5c = certificates.map((cert) => {
    const content = pemToDer(cert)
    if (!content) {
      throw new RegistrationCertificateError('Invalid PEM certificate format')
    }
    return content
  })

  const token = new Token(toRegistrationCertificateDialect(payload, dialect))
    .setProtectedHeader({ typ: 'rc-wrp+jwt', alg: algorithm, ...(keyId && { kid: keyId }) })
    .setX5c(x5c)
    .setSigningTime(signingTime)

  await token.sign(async (data) => signer(data))

  return {
    jws: token.toString(),
    header: token.getProtectedHeader() as RegistrationCertificateJwtHeader,
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
 */
export function decodeRegistrationCertificate(
  jws: string,
  accessCertificateSub: string
): SignedRegistrationCertificate {
  let decoded: ReturnType<typeof decode<RegistrationCertificatePayload>>
  try {
    decoded = decode<RegistrationCertificatePayload>(jws)
  } catch (error) {
    throw new RegistrationCertificateError(
      `Registration certificate signature does not meet the JAdES B-B profile (GEN-5.2.1-04): ${(error as Error).message}`,
      error
    )
  }

  // Validate typ header
  if (!isJwtTyp(decoded.header.typ, 'rc-wrp+jwt')) {
    throw new RegistrationCertificateError(
      `Invalid registration certificate type: expected "rc-wrp+jwt", got "${decoded.header.typ}"`
    )
  }

  // GEN-5.2.1-04
  const profile = validateProfile(decoded.header, JadesProfile.B_B, decoded.unprotectedHeader)
  if (!profile.valid) {
    throw new RegistrationCertificateError(
      `Registration certificate signature does not meet the JAdES B-B profile (GEN-5.2.1-04): ${profile.missing?.join(', ')}`
    )
  }

  // Validate payload structure
  const payload = parseRegistrationCertificatePayload(decoded.payload, accessCertificateSub)

  return {
    jws,
    header: decoded.header as RegistrationCertificateJwtHeader,
    payload,
  }
}

/**
 * Parse a registration certificate JWT without validation (for inspection purposes)
 *
 * @param jws - The compact JWS string
 * @returns Decoded parts without validation
 */
export function parseRegistrationCertificate(jws: string): { header: unknown; payload: unknown; signature: string } {
  const parts = jws.split('.')
  if (parts.length !== 3) {
    throw new RegistrationCertificateError('Invalid compact JWS: expected 3 parts')
  }
  const decoded = decode(jws)

  return {
    header: decoded.header,
    payload: decoded.payload,
    signature: parts[2],
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
