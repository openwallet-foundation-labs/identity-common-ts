/** JAdES signature builder for ETSI TS 119 182-1 V1.2.1. */
import { type Hasher, uint8ArrayToBase64Url } from '@owf/identity-common'
import { CRITICAL_PARAMETERS, DETACHED_MECHANISM_IDS } from './constants'
import { JAdESException } from './jades-exception'
import {
  ProtectedHeaderForSigningSchema,
  ProtectedHeaderParamsSchema,
  SigDSchema,
  UnprotectedHeaderSchema,
} from './schemas'
import type { FlattenedJWS, GeneralJWS, ProtectedHeaderParams, SigD, UnprotectedHeaderParams, X5tO } from './types'
import { encodeJSON, getSigningTime } from './utils'

const encoder = new TextEncoder()
const decoder = new TextDecoder()

function serializePayload(payload: unknown): { bytes: Uint8Array; text: string } {
  if (payload instanceof Uint8Array) return { bytes: payload, text: decoder.decode(payload) }
  if (typeof payload === 'string') return { bytes: encoder.encode(payload), text: payload }
  const serialized = JSON.stringify(payload)
  if (serialized === undefined) throw new JAdESException('Payload is not JSON serializable')
  return { bytes: encoder.encode(serialized), text: serialized }
}

function formatIssues(issues: ReadonlyArray<{ path: PropertyKey[]; message: string }>): string {
  return issues.map((issue) => `${issue.path.join('.') || 'header'}: ${issue.message}`).join(', ')
}

export class Token<T = unknown> {
  private protectedHeader: ProtectedHeaderParams = {}
  private unprotectedHeader: UnprotectedHeaderParams | undefined
  private payload: T | undefined
  private payloadBytes: Uint8Array
  private payloadText: string
  private detached = false
  private signature: string | undefined

  constructor(payload?: T) {
    this.payload = payload
    const serialized = payload === undefined ? { bytes: new Uint8Array(), text: '' } : serializePayload(payload)
    this.payloadBytes = serialized.bytes
    this.payloadText = serialized.text
  }

  setProtectedHeader(header: ProtectedHeaderParams): this {
    const merged = { ...this.protectedHeader, ...header }
    const result = ProtectedHeaderParamsSchema.safeParse(merged)
    if (!result.success) {
      throw new JAdESException(`Invalid protected header: ${formatIssues(result.error.issues)}`, result.error)
    }
    this.protectedHeader = result.data
    this.signature = undefined
    return this
  }

  setUnprotectedHeader(header: UnprotectedHeaderParams): this {
    const result = UnprotectedHeaderSchema.safeParse(header)
    if (!result.success) {
      throw new JAdESException(`Invalid unprotected header: ${formatIssues(result.error.issues)}`, result.error)
    }
    this.unprotectedHeader = result.data
    return this
  }

  setX5c(certs: string[]): this {
    return this.setProtectedHeader({ x5c: certs })
  }

  setX5u(uri: string): this {
    return this.setProtectedHeader({ x5u: uri })
  }

  setX5tS256(thumbprint: string): this {
    return this.setProtectedHeader({ 'x5t#S256': thumbprint })
  }

  setX5tO(x5tO: X5tO): this {
    return this.setProtectedHeader({ 'x5t#o': x5tO })
  }

  /** Set the current iat claimed signing time required for new signatures. */
  setSigningTime(time?: number | string | Date): this {
    let seconds: number
    if (typeof time === 'number') seconds = time
    else if (typeof time === 'string' || time instanceof Date) seconds = Math.floor(new Date(time).getTime() / 1000)
    else seconds = getSigningTime()
    if (!Number.isInteger(seconds)) throw new JAdESException('Signing time must resolve to integer Unix seconds')
    const header = { ...this.protectedHeader, iat: seconds }
    delete header.sigT
    return this.setProtectedHeader(header)
  }

  /** Set historical sigT for reproducing a signature created before 2025-07-15. */
  setLegacySigningTime(time: string): this {
    const header = { ...this.protectedHeader, sigT: time }
    delete header.iat
    return this.setProtectedHeader(header)
  }

  /** @deprecated Use setSigningTime. */
  setSignedAt(sec?: number): this {
    return this.setSigningTime(sec)
  }

  setIssuedAt(sec?: number): this {
    return this.setSigningTime(sec)
  }

  setKid(kid: string): this {
    return this.setProtectedHeader({ kid })
  }

  setContentType(cty: string): this {
    return this.setProtectedHeader({ cty })
  }

  setType(typ: string): this {
    return this.setProtectedHeader({ typ })
  }

  setB64(value: boolean): this {
    const header = { ...this.protectedHeader }
    if (value) delete header.b64
    else header.b64 = false
    this.protectedHeader = header
    this.signature = undefined
    return this
  }

  /**
   * Configure a detached payload. For direct-signing mechanisms, payload is the already
   * constructed JWS Payload. ObjectIdByURIHash always contributes an empty payload.
   */
  setDetached(sigD: SigD, payload?: T | string | Uint8Array): this {
    const result = SigDSchema.safeParse(sigD)
    if (!result.success) throw new JAdESException(`Invalid sigD: ${formatIssues(result.error.issues)}`, result.error)
    this.detached = true
    this.signature = undefined
    this.protectedHeader.sigD = result.data
    if (payload !== undefined) {
      this.payload = payload as T
      const serialized = serializePayload(payload)
      this.payloadBytes = serialized.bytes
      this.payloadText = serialized.text
    }
    if (sigD.mId === DETACHED_MECHANISM_IDS.httpHeaders) this.setB64(false)
    return this
  }

  getSigningInput(): string {
    return `${this.getEncodedProtectedHeader()}.${this.getSigningPayloadSegment()}`
  }

  /**
   * Hash the signing input with a caller-supplied hasher, so the package never
   * depends on a global Web Crypto implementation being present.
   *
   * @param hasher - Hashing callback, e.g. `hasher` from `@owf/crypto`
   * @param algorithm - Digest algorithm, defaulting to the one implied by `alg`
   */
  async getHash(hasher: Hasher, algorithm?: string): Promise<Uint8Array> {
    this.validateBeforeSign()
    const signingInput = encoder.encode(this.getSigningInput())
    return await hasher(signingInput.buffer as ArrayBuffer, algorithm ?? this.getHashAlgorithm())
  }

  setSignature(signature: string): this {
    this.validateBeforeSign()
    if (!/^[A-Za-z0-9_-]+$/.test(signature)) throw new JAdESException('Signature must be unpadded base64url')
    this.signature = signature
    return this
  }

  async sign(signer: (data: string) => Promise<string>): Promise<this> {
    this.validateBeforeSign()
    return this.setSignature(await signer(this.getSigningInput()))
  }

  toString(): string {
    const signature = this.getSignature()
    if (this.unprotectedHeader) throw new JAdESException('Compact JWS cannot carry the etsiU unprotected header')
    const payload = this.detached ? '' : this.getAttachedPayloadSegment()
    if (this.protectedHeader.b64 === false && payload.includes('.')) {
      throw new JAdESException('An unencoded compact JWS payload must not contain a period')
    }
    return `${this.getEncodedProtectedHeader()}.${payload}.${signature}`
  }

  toJSON(): GeneralJWS {
    const signature = this.getSignature()
    return {
      ...(this.detached ? {} : { payload: this.getAttachedPayloadSegment() }),
      signatures: [
        {
          protected: this.getEncodedProtectedHeader(),
          signature,
          ...(this.unprotectedHeader ? { header: this.unprotectedHeader } : {}),
        },
      ],
    }
  }

  toFlattenedJSON(): FlattenedJWS {
    const signature = this.getSignature()
    return {
      protected: this.getEncodedProtectedHeader(),
      signature,
      ...(this.detached ? {} : { payload: this.getAttachedPayloadSegment() }),
      ...(this.unprotectedHeader ? { header: this.unprotectedHeader } : {}),
    }
  }

  getProtectedHeader(): ProtectedHeaderParams {
    return { ...this.buildFinalHeader() }
  }

  getUnprotectedHeader(): UnprotectedHeaderParams | undefined {
    return this.unprotectedHeader ? { ...this.unprotectedHeader } : undefined
  }

  getPayload(): T | undefined {
    return this.payload
  }

  private getAttachedPayloadSegment(): string {
    return this.protectedHeader.b64 === false ? this.payloadText : uint8ArrayToBase64Url(this.payloadBytes)
  }

  private getSigningPayloadSegment(): string {
    if (this.protectedHeader.sigD?.mId === DETACHED_MECHANISM_IDS.objectByUriHash) return ''
    return this.getAttachedPayloadSegment()
  }

  private getEncodedProtectedHeader(): string {
    return encodeJSON(this.buildFinalHeader())
  }

  private buildFinalHeader(): ProtectedHeaderParams {
    const header = { ...this.protectedHeader }
    const crit = new Set(header.crit ?? [])
    for (const parameter of CRITICAL_PARAMETERS) if (parameter in header) crit.add(parameter)
    if (crit.size) header.crit = [...crit]
    return header
  }

  private validateBeforeSign(): void {
    const header = this.buildFinalHeader()
    const result = ProtectedHeaderForSigningSchema.safeParse(header)
    if (!result.success) {
      throw new JAdESException(
        `Invalid protected header for signing: ${formatIssues(result.error.issues)}`,
        result.error
      )
    }
    if (header.sigD && !this.detached) throw new JAdESException('sigD is only allowed with a detached payload')
    if (header.sigD && header.sigD.mId !== DETACHED_MECHANISM_IDS.objectByUriHash && this.payload === undefined) {
      throw new JAdESException('The constructed detached JWS Payload is required for this sigD mechanism')
    }
  }

  private getSignature(): string {
    if (!this.signature) throw new JAdESException('Token not signed yet')
    return this.signature
  }

  private getHashAlgorithm(): string {
    const match = this.protectedHeader.alg?.match(/(?:256|384|512)$/)?.[0]
    if (!match) throw new JAdESException(`Cannot infer hash algorithm from ${this.protectedHeader.alg}`)
    return `SHA-${match}`
  }
}
