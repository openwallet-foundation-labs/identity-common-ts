import { base64, base64url, type Finding, hex } from '@owf/identity-common'
import { InspectionError } from './inspection'

/** A document as pasted text, or as the bytes of a file or a response */
export type DocumentInput = string | Uint8Array

export const JWS = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$/
const HEX = /^(?:[0-9a-fA-F]{2})+$/
const BASE64 = /^[A-Za-z0-9+/]+={0,2}$/
const BASE64URL = /^[A-Za-z0-9_-]+$/

export const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value)

export const errorMessage = (error: unknown) => (error instanceof Error ? error.message : String(error))

export const withPathPrefix = (prefix: string, findings: Finding[]): Finding[] =>
  findings.map((finding) => ({ ...finding, path: [prefix, ...finding.path] }))

/** The input as trimmed text, without a byte order mark */
export const toText = (input: DocumentInput) =>
  (typeof input === 'string' ? input : new TextDecoder().decode(input)).replace(/^﻿/, '').trim()

/** Bytes given as hex, base64url or base64 text, or `undefined` when the text is none of them */
export function decodeBinaryText(text: string): Uint8Array | undefined {
  const compact = text.replace(/\s+/g, '')
  // Without a regular expression, which could take long on a long run of = that does not end the text
  let end = compact.length
  while (end > 0 && compact[end - 1] === '=') end--
  const unpadded = compact.slice(0, end)
  const decode = (decoder: () => Uint8Array) => {
    try {
      return decoder()
    } catch (error) {
      throw new InspectionError(`The input cannot be decoded: ${errorMessage(error)}`)
    }
  }
  if (HEX.test(compact)) return decode(() => hex.decode(compact))
  if (BASE64URL.test(unpadded)) return decode(() => base64url.decode(unpadded))
  if (BASE64.test(compact)) return decode(() => base64.decode(compact))
  return undefined
}

/** Whether the text is an SD-JWT in compact serialization */
export const isSdJwt = (text: string) => JWS.test(text.split('~')[0]) && text.includes('~')

/** Whether the bytes start with a CBOR map, or a map wrapped in tag 24 */
export const isCborMap = (bytes: Uint8Array) => (bytes[0] & 0xe0) === 0xa0 || (bytes[0] === 0xd8 && bytes[1] === 0x18)

/** The `typ` of a JOSE header, lowercase and without an `application/` prefix */
export const typOf = (header: Record<string, unknown>) =>
  typeof header.typ === 'string' ? header.typ.toLowerCase().replace(/^application\//, '') : undefined
