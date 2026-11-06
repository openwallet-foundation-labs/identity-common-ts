/**
 * JAdES Utility Functions
 *
 * Helper functions for certificate handling and header generation.
 */

import { parseCertificateChain, sha256, sha384, sha512 } from '@owf/crypto'
import { base64, uint8ArrayToBase64Url } from '@owf/identity-common'
import { JadesError } from './jades-error'
import type { X5tO } from './types'

/**
 * Generate x5c header value from PEM certificates.
 * The certificates are converted to base64-encoded DER format.
 *
 * ETSI TS 119 182-1 Section 5.1.8
 *
 * @param certs - PEM-encoded certificate(s) or array of base64 DER certs
 * @returns Array of base64-encoded DER certificate strings
 */
export function generateX5c(certs: string | string[]): string[] {
  if (typeof certs === 'string') {
    return parseCertificateChain(certs)
  }
  return certs
}

/**
 * Generate x5t#S256 header value (SHA-256 thumbprint of certificate).
 *
 * ETSI TS 119 182-1 Section 5.1.7
 *
 * @param certDer - Base64-encoded DER certificate
 * @returns Base64url-encoded SHA-256 thumbprint
 */
export function generateX5tS256(certDer: string): string {
  const certBytes = base64.decode(certDer)
  const hash = sha256(certBytes.buffer as ArrayBuffer)
  return uint8ArrayToBase64Url(hash)
}

/**
 * Generate x5t#o header value (certificate thumbprint with specified algorithm).
 *
 * ETSI TS 119 182-1 Section 5.2.2.2
 *
 * @param certDer - Base64-encoded DER certificate
 * @param algorithm - Hash algorithm ('SHA-384' or 'SHA-512')
 * @returns X5tO object with algorithm identifier and digest value
 */
export function generateX5tO(certDer: string, algorithm: 'SHA-384' | 'SHA-512' = 'SHA-512'): X5tO {
  const algMap = {
    'SHA-384': 'sha-384',
    'SHA-512': 'sha-512',
  } as const

  const hashFn = algorithm === 'SHA-384' ? sha384 : sha512
  const certBytes = base64.decode(certDer)
  const hash = hashFn(certBytes.buffer as ArrayBuffer)

  return {
    digAlg: algMap[algorithm],
    digVal: uint8ArrayToBase64Url(hash),
  }
}

/**
 * Generate sigX5ts header value (certificate chain thumbprints).
 *
 * ETSI TS 119 182-1 Section 5.2.2.3
 *
 * @param certsDer - Array of base64-encoded DER certificates
 * @param algorithm - Hash algorithm ('SHA-384' or 'SHA-512')
 * @returns Array of X5tO objects
 */
export function generateSigX5ts(certsDer: string[], algorithm: 'SHA-256' | 'SHA-384' | 'SHA-512' = 'SHA-512'): X5tO[] {
  if (certsDer.length < 2) {
    throw new JadesError('sigX5ts requires at least 2 certificates')
  }

  if (algorithm === 'SHA-256') {
    return certsDer.map((cert) => ({ digAlg: 'sha-256', digVal: generateX5tS256(cert) }))
  }
  return certsDer.map((cert) => generateX5tO(cert, algorithm))
}

/**
 * The current time as the integer Unix seconds of the `iat` claimed signing time.
 */
export function getSigningTime(): number {
  return Math.floor(Date.now() / 1000)
}
