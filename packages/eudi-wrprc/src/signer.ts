/**
 * WRPRC Signer
 *
 * Functions for creating and signing ETSI TS 119 475 Wallet-Relying Party Registration Certificates.
 *
 * @see https://www.etsi.org/deliver/etsi_ts/119400_119499/119475/01.02.01_60/ts_119475v010201p.pdf
 */

import { pemToDer } from '@owf/crypto'
import { base64urlEncode, decodeJwt } from '@owf/identity-common'
import type { SignedWRPRC, SignOptions, WRPRCJWTHeader, WRPRCPayload } from './types'
import { assertValidWRPRCPayload } from './validator'
import { WRPRCException } from './wrprc-exception'

// ============================================================================
// JWT Signing
// ============================================================================

/**
 * Sign a WRPRC payload to create a JWT
 *
 * @param options - Signing options including payload, algorithm, certificates, and signer
 * @returns Signed WRPRC with JWS string and decoded parts
 */
export async function signWRPRC(options: SignOptions): Promise<SignedWRPRC> {
  const { payload, algorithm = 'ES256', certificates, keyId, signer } = options

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

  // Create JWT header
  const header: WRPRCJWTHeader = {
    typ: 'rc-wrp+jwt',
    alg: algorithm,
    x5c,
    iat: Math.floor(Date.now() / 1000),
    ...(keyId && { kid: keyId }),
  }

  // Encode header and payload
  const encodedHeader = base64urlEncode(JSON.stringify(header))
  const encodedPayload = base64urlEncode(JSON.stringify(payload))
  const signingInput = `${encodedHeader}.${encodedPayload}`

  // Sign
  const signature = await signer(signingInput)

  // Create compact JWS
  const jws = `${signingInput}.${signature}`

  return {
    jws,
    header,
    payload,
  }
}

// ============================================================================
// JWT Decoding
// ============================================================================

/**
 * Decode a signed WRPRC JWT (without verification)
 *
 * @param jws - The compact JWS string
 * @returns Decoded WRPRC with header and payload
 */
export function decodeWRPRC(jws: string): SignedWRPRC {
  const decoded = decodeJwt(jws)

  // Validate typ header
  if (decoded.header.typ !== 'rc-wrp+jwt') {
    throw new WRPRCException(`Invalid WRPRC type: expected "rc-wrp+jwt", got "${decoded.header.typ}"`)
  }

  // Validate payload structure
  assertValidWRPRCPayload(decoded.payload)

  return {
    jws,
    header: decoded.header as WRPRCJWTHeader,
    payload: decoded.payload as WRPRCPayload,
  }
}

/**
 * Parse a WRPRC JWT without validation (for inspection purposes)
 *
 * @param jws - The compact JWS string
 * @returns Decoded parts without validation
 */
export function parseWRPRC(jws: string): { header: unknown; payload: unknown; signature: string } {
  const decoded = decodeJwt(jws)
  const parts = jws.split('.')

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
