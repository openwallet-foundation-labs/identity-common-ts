import { CryptoError } from './crypto-error'

/**
 * Parse PEM-encoded certificate(s) and return base64-encoded DER strings.
 *
 * @param pem - One or more PEM-encoded certificates
 * @returns Array of base64-encoded DER certificate strings
 */
export function parseCertificateChain(pem: string): string[] {
  const certs: string[] = []
  const certRegex = /-----BEGIN CERTIFICATE-----([\s\S]*?)-----END CERTIFICATE-----/g

  for (let match = certRegex.exec(pem); match !== null; match = certRegex.exec(pem)) {
    const base64Content = match[1].replace(/\s/g, '')
    certs.push(base64Content)
  }

  if (certs.length === 0) {
    throw new CryptoError('No valid certificates found in PEM string')
  }

  return certs
}

/**
 * Parse a PEM-encoded block and return its base64-encoded DER content.
 *
 * Supports any PEM type (certificates, private keys, public keys, etc.).
 *
 * @param pem - PEM-encoded string
 * @returns Base64-encoded DER string
 */
export function pemToDer(pem: string): string {
  const match = pem.match(/-----BEGIN [A-Z0-9 ]+-----([\s\S]*?)-----END [A-Z0-9 ]+-----/)

  if (!match) {
    throw new CryptoError('No valid PEM block found')
  }

  return match[1].replace(/\s/g, '')
}

/**
 * Parse a single PEM-encoded certificate and return its base64-encoded DER string.
 *
 * @param pem - A single PEM-encoded certificate
 * @returns Base64-encoded DER certificate string
 */
export function parseCertificate(pem: string): string {
  const certRegex = /-----BEGIN CERTIFICATE-----([\s\S]*?)-----END CERTIFICATE-----/
  const match = pem.match(certRegex)

  if (!match) {
    throw new CryptoError('No valid certificate found in PEM string')
  }

  return match[1].replace(/\s/g, '')
}

/**
 * Convert a base64-encoded DER certificate to PEM format.
 *
 * @param base64Der - Base64-encoded DER certificate data
 * @returns PEM-encoded certificate string
 */
export function base64DerToPem(base64Der: string): string {
  const lines = base64Der.match(/.{1,64}/g) || []
  return `-----BEGIN CERTIFICATE-----\n${lines.join('\n')}\n-----END CERTIFICATE-----`
}
