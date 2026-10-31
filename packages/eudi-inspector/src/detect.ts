import { decodeJwt } from '@owf/identity-common'
import { type DocumentInput, decodeBinaryText, errorMessage, isCborMap, isSdJwt, JWS, toText, typOf } from './input'
import { type DocumentKind, InspectionError } from './inspection'

/** A kind of document, as opposed to the over-asking check of a request */
export type DocumentFormat = Exclude<DocumentKind, 'over-asking'>

function detectBytes(bytes: Uint8Array): DocumentFormat | undefined {
  // DER starts with a SEQUENCE and an mdoc with a CBOR map, which no supported text format does
  if (bytes[0] === 0x30) return 'access-certificate'
  if (isCborMap(bytes)) return 'mdoc'
  return undefined
}

function detectJws(jws: string): DocumentFormat {
  let decoded: { header: Record<string, unknown>; payload: Record<string, unknown> }
  try {
    decoded = decodeJwt<Record<string, unknown>, Record<string, unknown>>(jws)
  } catch (error) {
    throw new InspectionError(`This looks like a JWS, but it cannot be decoded: ${errorMessage(error)}`)
  }
  const { header, payload } = decoded
  const typ = typOf(header)
  if (typ === 'rc-wrp+jwt') return 'registration-certificate'
  if (typ === 'dc+sd-jwt' || typ === 'vc+sd-jwt') return 'sd-jwt'
  if (typ === 'statuslist+jwt' || 'status_list' in payload) return 'status-list'
  if ('LoTE' in payload) return 'lote'
  throw new InspectionError(
    `This JWS has the typ ${String(header.typ ?? '(none)')} and is neither a registration certificate (rc-wrp+jwt), a status list (statuslist+jwt) nor a LoTE`
  )
}

/**
 * Recognise the format of a document from its first characters, or for a JWS from its
 * header, without parsing it.
 *
 * @throws InspectionError when the input is none of the supported formats
 */
export function detect(input: DocumentInput): DocumentFormat {
  const binary = typeof input === 'string' ? undefined : detectBytes(input)
  if (binary) return binary

  const text = toText(input)
  if (!text) throw new InspectionError('There is nothing to inspect')
  if (text.startsWith('<')) return 'trusted-list'
  if (text.includes('-----BEGIN CERTIFICATE-----')) return 'access-certificate'
  if (text.startsWith('{')) return 'lote'
  if (isSdJwt(text)) return 'sd-jwt'
  if (JWS.test(text)) return detectJws(text)

  // A certificate or an mdoc as text
  const bytes = decodeBinaryText(text)
  if (bytes) {
    const format = detectBytes(bytes)
    if (format) return format
    throw new InspectionError('The decoded bytes are neither a DER certificate nor the CBOR of an mdoc')
  }
  throw new InspectionError(
    'Unrecognised input. Expected a trusted list (XML), a LoTE (JSON or JWS), a registration certificate or status list (JWT), an SD-JWT, an mdoc (CBOR as hex or base64url) or a certificate (PEM, base64 or DER).'
  )
}
