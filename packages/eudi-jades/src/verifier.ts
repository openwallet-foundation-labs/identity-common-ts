/** JAdES JWS decoding and cryptographic verification. */
import { base64UrlToUint8Array, base64urlDecode, uint8ArrayToBase64Url } from '@owf/identity-common'
import { CRITICAL_PARAMETERS, DETACHED_MECHANISM_IDS } from './constants'
import { JAdESException } from './jades-exception'
import { FlattenedJWSSchema, GeneralJWSSchema, ProtectedHeaderSchema, UnprotectedHeaderSchema } from './schemas'
import type { FlattenedJWS, GeneralJWS, ProtectedHeader, UnprotectedHeaderParams, VerifyOptions } from './types'

const decoder = new TextDecoder()
const encoder = new TextEncoder()

export interface VerifyResult<T = unknown> {
  header: ProtectedHeader
  payload: T
  rawPayload: string
  rawPayloadBytes: Uint8Array
  unprotectedHeader?: UnprotectedHeaderParams
  valid: boolean
}

interface ParsedSignature<T> extends Omit<VerifyResult<T>, 'valid'> {
  signingInput: string
  signature: string
}

function formatIssues(issues: ReadonlyArray<{ path: PropertyKey[]; message: string }>): string {
  return issues.map((issue) => `${issue.path.join('.') || 'header'}: ${issue.message}`).join(', ')
}

function parseProtected(encoded: string | undefined): ProtectedHeader {
  if (!encoded) throw new JAdESException('JAdES requires a JWS Protected Header')
  let raw: unknown
  try {
    raw = JSON.parse(base64urlDecode(encoded))
  } catch (error) {
    throw new JAdESException('Invalid protected header encoding', error)
  }
  const result = ProtectedHeaderSchema.safeParse(raw)
  if (!result.success) {
    throw new JAdESException(`Invalid protected header: ${formatIssues(result.error.issues)}`, result.error)
  }
  return result.data as ProtectedHeader
}

function parseUnprotected(raw: unknown): UnprotectedHeaderParams | undefined {
  if (raw === undefined) return undefined
  const result = UnprotectedHeaderSchema.safeParse(raw)
  if (!result.success) {
    throw new JAdESException(`Invalid unprotected header: ${formatIssues(result.error.issues)}`, result.error)
  }
  return result.data
}

function detachedBytes(payload: VerifyOptions['detachedPayload']): Uint8Array | undefined {
  if (payload === undefined) return undefined
  return typeof payload === 'string' ? encoder.encode(payload) : payload
}

function parsePayload<T>(value: string): T {
  if (value === '') return undefined as T
  try {
    return JSON.parse(value) as T
  } catch {
    return value as T
  }
}

function parseSignature<T>(
  encodedHeader: string | undefined,
  serializedPayload: string | undefined,
  signature: string,
  unprotected: unknown,
  options: VerifyOptions
): ParsedSignature<T> {
  const header = parseProtected(encodedHeader)
  const understoodCriticalParameters = new Set([
    ...CRITICAL_PARAMETERS,
    ...(options.understoodCriticalParameters ?? []),
  ])
  const unsupportedCriticalParameter = header.crit?.find((parameter) => !understoodCriticalParameters.has(parameter))
  if (unsupportedCriticalParameter) {
    throw new JAdESException(`Unsupported critical header parameter: ${unsupportedCriticalParameter}`)
  }
  const suppliedBytes = detachedBytes(options.detachedPayload)
  const suppliedPayload = suppliedBytes ? decoder.decode(suppliedBytes) : undefined
  const objectDigest = header.sigD?.mId === DETACHED_MECHANISM_IDS.objectByUriHash

  if (serializedPayload === undefined && suppliedPayload === undefined && !objectDigest) {
    throw new JAdESException('Detached JWS payload is required for verification')
  }

  const signingPayload = objectDigest
    ? ''
    : suppliedPayload === undefined
      ? (serializedPayload ?? '')
      : header.b64 === false
        ? suppliedPayload
        : uint8ArrayToBase64Url(suppliedBytes as Uint8Array)

  const rawPayloadBytes =
    suppliedBytes ??
    (serializedPayload === undefined
      ? new Uint8Array()
      : header.b64 === false
        ? encoder.encode(serializedPayload)
        : base64UrlToUint8Array(serializedPayload))
  const rawPayload = decoder.decode(rawPayloadBytes)

  return {
    header,
    payload: parsePayload<T>(rawPayload),
    rawPayload,
    rawPayloadBytes,
    unprotectedHeader: parseUnprotected(unprotected),
    signingInput: `${encodedHeader}.${signingPayload}`,
    signature,
  }
}

async function verifyParsed<T>(
  parsed: ParsedSignature<T>,
  verifier: (data: string, signature: string) => Promise<boolean>
): Promise<VerifyResult<T>> {
  if (!(await verifier(parsed.signingInput, parsed.signature))) throw new JAdESException('Invalid signature')
  const { signingInput: _, signature: __, ...result } = parsed
  return { ...result, valid: true }
}

export async function verifyCompact<T = unknown>(
  jws: string,
  verifier: (data: string, signature: string) => Promise<boolean>,
  options: VerifyOptions = {}
): Promise<VerifyResult<T>> {
  const parts = jws.split('.')
  if (parts.length !== 3) throw new JAdESException('Invalid compact JWS: expected 3 parts')
  return verifyParsed(parseSignature<T>(parts[0], parts[1], parts[2], undefined, options), verifier)
}

export async function verifyGeneral<T = unknown>(
  generalJws: GeneralJWS,
  verifier: (data: string, signature: string) => Promise<boolean>,
  signatureIndex = 0,
  options: VerifyOptions = {}
): Promise<VerifyResult<T>> {
  const result = GeneralJWSSchema.safeParse(generalJws)
  if (!result.success) {
    throw new JAdESException(`Invalid General JWS: ${formatIssues(result.error.issues)}`, result.error)
  }
  const selected = result.data.signatures[signatureIndex]
  if (!selected) throw new JAdESException(`Signature at index ${signatureIndex} not found`)
  return verifyParsed(
    parseSignature<T>(selected.protected, result.data.payload, selected.signature, selected.header, options),
    verifier
  )
}

export async function verifyFlattened<T = unknown>(
  flattenedJws: FlattenedJWS,
  verifier: (data: string, signature: string) => Promise<boolean>,
  options: VerifyOptions = {}
): Promise<VerifyResult<T>> {
  const result = FlattenedJWSSchema.safeParse(flattenedJws)
  if (!result.success) {
    throw new JAdESException(`Invalid Flattened JWS: ${formatIssues(result.error.issues)}`, result.error)
  }
  return verifyParsed(
    parseSignature<T>(result.data.protected, result.data.payload, result.data.signature, result.data.header, options),
    verifier
  )
}

export async function verify<T = unknown>(
  jws: string | GeneralJWS | FlattenedJWS,
  verifier: (data: string, signature: string) => Promise<boolean>,
  options: VerifyOptions = {}
): Promise<VerifyResult<T>> {
  if (typeof jws !== 'string') {
    return 'signatures' in jws
      ? verifyGeneral(jws, verifier, options.signatureIndex ?? 0, options)
      : verifyFlattened(jws, verifier, options)
  }
  try {
    const parsed = JSON.parse(jws) as GeneralJWS | FlattenedJWS
    return await verify(parsed, verifier, options)
  } catch (error) {
    if (error instanceof JAdESException) throw error
    return verifyCompact(jws, verifier, options)
  }
}

export function decode<T = unknown>(
  jws: string | GeneralJWS | FlattenedJWS,
  options: VerifyOptions = {}
): Omit<VerifyResult<T>, 'valid'> {
  let parsed: ParsedSignature<T>
  if (typeof jws === 'string') {
    try {
      return decode(JSON.parse(jws) as GeneralJWS | FlattenedJWS, options)
    } catch (error) {
      if (error instanceof JAdESException) throw error
      const parts = jws.split('.')
      if (parts.length !== 3) throw new JAdESException('Invalid compact JWS: expected 3 parts')
      parsed = parseSignature(parts[0], parts[1], parts[2], undefined, options)
    }
  } else if ('signatures' in jws) {
    const result = GeneralJWSSchema.safeParse(jws)
    if (!result.success) throw new JAdESException(`Invalid General JWS: ${formatIssues(result.error.issues)}`)
    const signature = result.data.signatures[options.signatureIndex ?? 0]
    if (!signature) throw new JAdESException(`Signature at index ${options.signatureIndex ?? 0} not found`)
    parsed = parseSignature(signature.protected, result.data.payload, signature.signature, signature.header, options)
  } else {
    const result = FlattenedJWSSchema.safeParse(jws)
    if (!result.success) throw new JAdESException(`Invalid Flattened JWS: ${formatIssues(result.error.issues)}`)
    parsed = parseSignature(
      result.data.protected,
      result.data.payload,
      result.data.signature,
      result.data.header,
      options
    )
  }
  const { signingInput: _, signature: __, ...decoded } = parsed
  return decoded
}
