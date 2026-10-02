import { base64 } from '@owf/identity-common'
import { X509Exception } from './x509-exception'

/** DER bytes, a base64 encoded DER string, or a PEM string */
export type DerInput = Uint8Array | ArrayBuffer | string

/** A DER encoded certificate as bytes, a base64 DER string, or a PEM string */
export type CertificateInput = DerInput

/** A DER encoded CRL as bytes, a base64 DER string, or a PEM string (`X509 CRL`) */
export type CrlInput = DerInput

export const PEM_LABELS = {
  certificate: 'CERTIFICATE',
  crl: 'X509 CRL',
} as const

/**
 * Normalize a {@link DerInput} to DER bytes. PEM strings must use the given label; the
 * first matching block is used.
 */
export function toDer(input: DerInput, label: string = PEM_LABELS.certificate): Uint8Array {
  if (input instanceof Uint8Array) return input
  if (input instanceof ArrayBuffer) return new Uint8Array(input)
  if (typeof input !== 'string') {
    throw new X509Exception('Input must be DER bytes, a base64 DER string, or PEM')
  }
  let body = input
  if (input.includes('-----BEGIN')) {
    const pem = input.match(new RegExp(`-----BEGIN ${label}-----([\\s\\S]*?)-----END ${label}-----`))
    if (!pem) throw new X509Exception(`No PEM block with label "${label}" found`)
    body = pem[1]
  }
  body = body.replace(/\s/g, '')
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(body)) {
    throw new X509Exception('Input is neither PEM nor base64 encoded DER')
  }
  return base64.decode(body)
}

/** Encode DER bytes as PEM. */
export function toPem(der: Uint8Array, label: string = PEM_LABELS.certificate): string {
  const lines = base64.encode(der).match(/.{1,64}/g) ?? []
  return `-----BEGIN ${label}-----\n${lines.join('\n')}\n-----END ${label}-----\n`
}

/** Copy bytes into a standalone ArrayBuffer (asn1-schema works on ArrayBuffers). */
export function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  return bytes.slice().buffer as ArrayBuffer
}
