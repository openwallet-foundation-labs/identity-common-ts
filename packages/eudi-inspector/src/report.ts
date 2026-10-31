import type { Finding } from '@owf/identity-common'
import type { DocumentKind, Inspection, SignatureResult } from './inspection'

/** An inspection with its signatures verified, as plain data that can be serialized as JSON */
export interface InspectionReport {
  kind: DocumentKind
  title: string
  /** No finding is an error, and no signature is invalid */
  valid: boolean
  checks: string[]
  notes: string[]
  facts: Record<string, string>
  findings: Finding[]
  signatures: (SignatureResult & { label: string })[]
  /** The parsed document, with bytes as hex, see {@link toJson} */
  value: unknown
}

const toHex = (bytes: Uint8Array) => Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('')

/**
 * The value as data that `JSON.stringify` keeps: bytes as hex, maps as objects, big
 * integers as strings, and dates as ISO 8601 strings.
 */
export function toJson(value: unknown): unknown {
  if (value instanceof Date) return Number.isNaN(value.getTime()) ? null : value.toISOString()
  if (value instanceof ArrayBuffer) return toHex(new Uint8Array(value))
  if (ArrayBuffer.isView(value)) return toHex(new Uint8Array(value.buffer, value.byteOffset, value.byteLength))
  if (typeof value === 'bigint') return value.toString()
  if (value instanceof Map) return Object.fromEntries([...value].map(([key, entry]) => [String(key), toJson(entry)]))
  if (Array.isArray(value)) return value.map(toJson)
  if (typeof value === 'object' && value !== null) {
    return Object.fromEntries(
      Object.entries(value)
        .filter(([, entry]) => entry !== undefined && typeof entry !== 'function')
        .map(([key, entry]) => [key, toJson(entry)])
    )
  }
  return value
}

/**
 * Verify the signatures of an inspection and return it as plain data.
 *
 * @param crypto The Web Crypto implementation to verify with, e.g. `globalThis.crypto`
 */
export async function report(inspection: Inspection, crypto: Crypto): Promise<InspectionReport> {
  const signatures = await Promise.all(
    (inspection.signatures ?? []).map(async ({ label, verify }) => ({ label, ...(await verify(crypto)) }))
  )
  return {
    kind: inspection.kind,
    title: inspection.title,
    valid:
      inspection.findings.every((finding) => finding.severity !== 'error') &&
      signatures.every((signature) => signature.status !== 'invalid'),
    checks: inspection.checks,
    notes: inspection.notes,
    facts: Object.fromEntries(inspection.facts ?? []),
    findings: inspection.findings,
    signatures,
    value: toJson(inspection.value),
  }
}
