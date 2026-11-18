import { CryptoError } from './crypto-error'

/**
 * Parse PEM-encoded certificate(s) and return base64-encoded DER strings.
 *
 * @param pem - One or more PEM-encoded certificates
 * @returns Array of base64-encoded DER certificate strings
 */
export function parseCertificateChain(pem: string): string[] {
  const certs: string[] = []

  for (let block = findPemBlock(pem, 'CERTIFICATE'); block; block = findPemBlock(pem, 'CERTIFICATE', block.end)) {
    certs.push(block.content.replace(/\s/g, ''))
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
  const block = findPemBlock(pem)

  if (!block) {
    throw new CryptoError('No valid PEM block found')
  }

  return block.content.replace(/\s/g, '')
}

/**
 * Parse a single PEM-encoded certificate and return its base64-encoded DER string.
 *
 * @param pem - A single PEM-encoded certificate
 * @returns Base64-encoded DER certificate string
 */
export function parseCertificate(pem: string): string {
  const block = findPemBlock(pem, 'CERTIFICATE')

  if (!block) {
    throw new CryptoError('No valid certificate found in PEM string')
  }

  return block.content.replace(/\s/g, '')
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

/**
 * Find the first PEM block (RFC 7468 Section 2) at or after `from`, with the given label, or with any label of
 * `A-Z`, `0-9` and spaces.
 *
 * The boundaries are searched with `indexOf`, because a regular expression that matches lazily up to the
 * post-encapsulation boundary takes quadratic time on input with many pre-encapsulation boundaries.
 */
function findPemBlock(pem: string, label?: string, from = 0): { content: string; end: number } | undefined {
  const begin = findBoundary(pem, 'BEGIN', label, from)
  if (!begin) return undefined

  const end = findBoundary(pem, 'END', label, begin.end)
  if (!end) return undefined

  return { content: pem.slice(begin.end, end.start), end: end.end }
}

function findBoundary(
  pem: string,
  keyword: 'BEGIN' | 'END',
  label: string | undefined,
  from: number
): { start: number; end: number } | undefined {
  if (label !== undefined) {
    const boundary = `-----${keyword} ${label}-----`
    const start = pem.indexOf(boundary, from)
    return start === -1 ? undefined : { start, end: start + boundary.length }
  }

  const prefix = `-----${keyword} `
  for (let start = pem.indexOf(prefix, from); start !== -1; start = pem.indexOf(prefix, from)) {
    const labelStart = start + prefix.length
    let labelEnd = labelStart
    while (labelEnd < pem.length && isLabelCharacter(pem.charCodeAt(labelEnd))) labelEnd++

    if (labelEnd > labelStart && pem.startsWith('-----', labelEnd)) return { start, end: labelEnd + 5 }

    // A boundary starts with a hyphen, so the next one can't start inside the label
    from = labelEnd
  }

  return undefined
}

function isLabelCharacter(code: number): boolean {
  // A-Z, 0-9 and space
  return (code >= 0x41 && code <= 0x5a) || (code >= 0x30 && code <= 0x39) || code === 0x20
}
