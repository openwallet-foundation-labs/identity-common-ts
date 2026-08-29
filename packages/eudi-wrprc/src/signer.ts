/**
 * WRPRC Signer
 *
 * Functions for creating and signing ETSI TS 119 475 Wallet-Relying Party Registration Certificates.
 *
 * GEN-5.2.1-04 requires the JWT to carry a JAdES signature with the B-B profile of
 * ETSI TS 119 182-1, so signing and decoding go through `@owf/eudi-jades`.
 *
 * @see https://www.etsi.org/deliver/etsi_ts/119400_119499/119475/01.02.01_60/ts_119475v010201p.pdf
 */

import { pemToDer } from '@owf/crypto'
import { decode, JAdESProfile, Token, validateProfile } from '@owf/eudi-jades'
import { toWRPRCDialect, WRPRC_DIALECTS } from './dialect'
import type { SignedWRPRC, SignOptions, WRPRCJWTHeader, WRPRCPayload } from './types'
import { assertValidWRPRCPayload, parseWRPRCPayload } from './validator'
import { WRPRCException } from './wrprc-exception'

// ============================================================================
// JWT Signing
// ============================================================================

/**
 * Sign a WRPRC payload into a JAdES B-B signed JWT
 *
 * @param options - Signing options including payload, algorithm, certificates, and signer
 * @returns Signed WRPRC with JWS string and decoded parts
 */
export async function signWRPRC(options: SignOptions): Promise<SignedWRPRC> {
  const {
    payload,
    algorithm = 'ES256',
    certificates,
    keyId,
    signer,
    signingTime,
    dialect = WRPRC_DIALECTS.CURRENT,
  } = options

  // Validate payload
  assertValidWRPRCPayload(payload)

  if (!certificates || certificates.length === 0) {
    throw new WRPRCException('At least one certificate is required for x5c header')
  }

  // Extract base64 content from PEM certificates
  const x5c = certificates.map((cert) => {
    const content = pemToDer(cert)
    if (!content) {
      throw new WRPRCException('Invalid PEM certificate format')
    }
    return content
  })

  const token = new Token(toWRPRCDialect(payload, dialect))
    .setProtectedHeader({ typ: 'rc-wrp+jwt', alg: algorithm, ...(keyId && { kid: keyId }) })
    .setX5c(x5c)
    .setSigningTime(signingTime)

  await token.sign(signer)

  return {
    jws: token.toString(),
    header: token.getProtectedHeader() as WRPRCJWTHeader,
    payload,
  }
}

// ============================================================================
// JWT Decoding
// ============================================================================

/**
 * Decode a signed WRPRC JWT (without cryptographic verification)
 *
 * @param jws - The compact JWS string
 * @returns Decoded WRPRC with header and payload
 */
export function decodeWRPRC(jws: string): SignedWRPRC {
  let decoded: ReturnType<typeof decode<WRPRCPayload>>
  try {
    decoded = decode<WRPRCPayload>(jws)
  } catch (error) {
    throw new WRPRCException(
      `WRPRC signature does not meet the JAdES B-B profile (GEN-5.2.1-04): ${(error as Error).message}`,
      error
    )
  }

  // Validate typ header
  if (decoded.header.typ !== 'rc-wrp+jwt') {
    throw new WRPRCException(`Invalid WRPRC type: expected "rc-wrp+jwt", got "${decoded.header.typ}"`)
  }

  // GEN-5.2.1-04
  const profile = validateProfile(decoded.header, JAdESProfile.B_B, decoded.unprotectedHeader)
  if (!profile.valid) {
    throw new WRPRCException(
      `WRPRC signature does not meet the JAdES B-B profile (GEN-5.2.1-04): ${profile.missing?.join(', ')}`
    )
  }

  // Validate payload structure
  const payload = parseWRPRCPayload(decoded.payload)

  return {
    jws,
    header: decoded.header as WRPRCJWTHeader,
    payload,
  }
}

/**
 * Parse a WRPRC JWT without validation (for inspection purposes)
 *
 * @param jws - The compact JWS string
 * @returns Decoded parts without validation
 */
export function parseWRPRC(jws: string): { header: unknown; payload: unknown; signature: string } {
  const parts = jws.split('.')
  if (parts.length !== 3) {
    throw new WRPRCException('Invalid compact JWS: expected 3 parts')
  }
  const decoded = decode(jws)

  return {
    header: decoded.header,
    payload: decoded.payload,
    signature: parts[2],
  }
}

// ============================================================================
// WRPRC Creation Helpers
// ============================================================================

/**
 * Create a WRPRC with automatic timestamp
 *
 * @param payload - Partial payload (iat will be set automatically if not provided)
 * @returns Complete payload with timestamp
 */
export function createWRPRCPayload(payload: WRPRCPayload): WRPRCPayload {
  assertValidWRPRCPayload(payload)

  return payload
}
