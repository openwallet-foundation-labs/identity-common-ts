import { addExtension } from 'cbor-x'
import z from 'zod'
import {
  type AnyCborStructure,
  CborStructure,
  type CborStructureStaticThis,
  cborDecode,
  cborEncode,
  type EncodedStructureType,
} from '../cbor'
import { zUint8Array } from '../utils/zod'
import { CoseCertificateNotFoundError, CoseInvalidAlgorithmError, CosePayloadMustBeDefinedError } from './error'
import {
  type ProtectedHeaderOptions,
  ProtectedHeaders,
  protectedHeadersEncodedStructure,
  RegisteredCwtHeaderClaimKey,
  type SignatureAlgorithm,
  type UnprotectedHeaderOptions,
  UnprotectedHeaders,
  unprotectedHeadersStructure,
} from './headers'
import { type CoseKey, coseKeyToJwkClaim } from './key'

export const sign1EncodedSchema = z.tuple([
  // protected headers
  protectedHeadersEncodedStructure,
  // unprotected headers
  unprotectedHeadersStructure,
  // payload
  zUint8Array.nullable(),
  // signature
  zUint8Array,
])

export const sign1DecodedSchema = z.object({
  protectedHeaders: z.instanceof(ProtectedHeaders),
  unprotectedHeaders: z.instanceof(UnprotectedHeaders),
  payload: sign1EncodedSchema.def.items[2],
  signature: sign1EncodedSchema.def.items[3],
})

export type Sign1EncodedStructure = z.infer<typeof sign1EncodedSchema>
export type Sign1DecodedStructure = z.infer<typeof sign1DecodedSchema>

export type Sign1Context = {
  sign: (options: { toBeSigned: Uint8Array; key: CoseKey; algorithm: SignatureAlgorithm }) => Promise<Uint8Array>
  verify: (options: { toBeVerified: Uint8Array; signature: Uint8Array; key: CoseKey }) => Promise<boolean>
  x509: {
    getIssuerNameField: (options: { certificate: Uint8Array; field: string }) => string[]
    getPublicKey: (options: { certificate: Uint8Array; alg: string }) => Promise<CoseKey>
  }
}

export type Sign1Options = {
  protectedHeaders?: ProtectedHeaders | ProtectedHeaderOptions['protectedHeaders']
  unprotectedHeaders?: UnprotectedHeaders | UnprotectedHeaderOptions['unprotectedHeaders']
  externalAad?: Uint8Array

  /**
   * The embedded payload. Pass `null` to explicitly signal a detached payload
   * (the encoded structure will contain null, and you must supply the payload
   * via `detachedPayload` when calling `sign()` / `verifySignature()` / `toBeSigned()`).
   */
  payload: Uint8Array | null
}

export class Sign1 extends CborStructure<Sign1EncodedStructure, Sign1DecodedStructure> {
  public static tag = 18
  protected override _tag = Sign1.tag

  public static override get encodingSchema() {
    return z.codec(sign1EncodedSchema, sign1DecodedSchema, {
      encode: (decoded) => {
        if (decoded.signature.length === 0) {
          throw new Error('Signature has not been set. Required for encoding the sign1 structure')
        }

        return [
          decoded.protectedHeaders.encodedStructure,
          decoded.unprotectedHeaders.encodedStructure,
          decoded.payload,
          decoded.signature,
        ] satisfies Sign1EncodedStructure
      },
      decode: ([protectedHeaders, unprotected, payload, signature]) => ({
        protectedHeaders: ProtectedHeaders.fromEncodedStructure(protectedHeaders),
        unprotectedHeaders: UnprotectedHeaders.fromEncodedStructure(unprotected),
        payload,
        signature,
      }),
    })
  }

  public externalAad?: Uint8Array

  public get protectedHeaders() {
    return this.structure.protectedHeaders
  }

  public get unprotectedHeaders() {
    return this.structure.unprotectedHeaders
  }

  public get payload() {
    return this.structure.payload
  }

  public get signature() {
    return this.structure.signature
  }

  public get certificateChain() {
    return this.x5chain ?? []
  }

  public get certificate() {
    const [certificate] = this.certificateChain

    if (!certificate) {
      throw new CoseCertificateNotFoundError()
    }

    return certificate
  }

  public getIssuingCountry(ctx: Pick<Sign1Context, 'x509'>) {
    const countryName = ctx.x509.getIssuerNameField({
      certificate: this.certificate,
      field: 'C',
    })[0]

    return countryName
  }

  public getIssuingStateOrProvince(ctx: Pick<Sign1Context, 'x509'>) {
    const stateOrProvince = ctx.x509.getIssuerNameField({
      certificate: this.certificate,
      field: 'ST',
    })[0]

    return stateOrProvince
  }

  /**
   * Returns the Sig_Structure bytes that are signed/verified.
   *
   * @param options.detachedPayload - The detached payload to use. Must be provided when
   *   the Sign1 was created with a detached payload (i.e. `payload` field is null).
   *   Cannot be provided when the Sign1 already contains an embedded payload.
   */
  public toBeSigned(options?: { detachedPayload?: Uint8Array }): Uint8Array {
    const embeddedPayload = this.payload
    const detachedPayload = options?.detachedPayload

    if (embeddedPayload && detachedPayload) {
      throw new Error('Cannot provide detachedPayload when the Sign1 already contains an embedded payload')
    }

    const payload = embeddedPayload ?? detachedPayload

    if (!payload) {
      throw new CosePayloadMustBeDefinedError()
    }

    return Sign1.toBeSigned({
      payload,
      protectedHeaders: this.protectedHeaders,
      externalAad: this.externalAad,
    })
  }

  /**
   * Decodes CBOR bytes into a Sign1 instance.
   * Uses the encodingSchema's decode() method to validate and transform the decoded data.
   */
  public static decode<T extends AnyCborStructure>(this: CborStructureStaticThis<T>, bytes: Uint8Array): T {
    const rawStructure = cborDecode(bytes)

    // May feel weird, but using new this makes TypeScript understand we may return a subclass
    // biome-ignore lint/complexity/noThisInStatic: this.decode is intentional for subclass support
    return new this(
      // NOTE: If decoded with Sign1 tag, the cbor decoder already transforms to the class instances
      // In that case we create new instance based on the decoded structure, to ensure we create the
      // instance based on this (and ensure extended classes work)
      rawStructure instanceof Sign1
        ? rawStructure.decodedStructure
        : Sign1.fromEncodedStructure(rawStructure as EncodedStructureType<T>).decodedStructure
    ) as unknown as T
  }

  public static toBeSigned(options: {
    payload: Uint8Array
    protectedHeaders: ProtectedHeaders
    externalAad?: Uint8Array
  }) {
    const toBeSigned = [
      'Signature1',
      options.protectedHeaders.encodedStructure,
      options.externalAad ?? new Uint8Array(),
      options.payload,
    ]

    return cborEncode(toBeSigned)
  }

  public get signatureAlgorithmName(): string {
    // FIXME: why are we looking at the unprotected header for the alg?
    const algorithm = (this.protectedHeaders.headers?.get(RegisteredCwtHeaderClaimKey.Algorithm) ??
      this.unprotectedHeaders.headers?.get(RegisteredCwtHeaderClaimKey.Algorithm)) as SignatureAlgorithm | undefined

    if (!algorithm) {
      throw new CoseInvalidAlgorithmError()
    }

    const algorithmName = coseKeyToJwkClaim.algorithm(algorithm)
    if (!algorithmName) {
      throw new CoseInvalidAlgorithmError()
    }

    return algorithmName
  }

  public get x5chain() {
    // TODO: typed keys for headers
    // FIXME: why are we looking at unprotected header for x5c?
    const x5chain =
      (this.protectedHeaders.headers?.get(RegisteredCwtHeaderClaimKey.X5Chain) as
        | Uint8Array
        | Uint8Array[]
        | undefined) ??
      (this.unprotectedHeaders.headers?.get(RegisteredCwtHeaderClaimKey.X5Chain) as
        | Uint8Array
        | Uint8Array[]
        | undefined)

    if (!x5chain?.[0]) {
      return undefined
    }

    return Array.isArray(x5chain) ? x5chain : [x5chain]
  }

  public async verifySignature(
    options: { key?: CoseKey; detachedPayload?: Uint8Array },
    ctx: Pick<Sign1Context, 'verify' | 'x509'>
  ) {
    const embeddedPayload = this.payload
    const { detachedPayload } = options

    if (embeddedPayload && detachedPayload) {
      throw new Error('Cannot provide detachedPayload when the Sign1 already contains an embedded payload')
    }

    const publicKey =
      options.key ??
      (this.certificate
        ? await ctx.x509.getPublicKey({
            certificate: this.certificate,
            alg: this.signatureAlgorithmName,
          })
        : undefined)

    if (!publicKey) {
      throw new CoseCertificateNotFoundError()
    }

    return await ctx.verify({
      toBeVerified: this.toBeSigned({ detachedPayload }),
      signature: this.signature,
      key: publicKey,
    })
  }

  public static create(options: Sign1Options) {
    const protectedHeaders =
      options.protectedHeaders instanceof ProtectedHeaders
        ? options.protectedHeaders
        : options.protectedHeaders
          ? ProtectedHeaders.fromDecodedStructure(options.protectedHeaders)
          : ProtectedHeaders.create({})

    const unprotectedHeaders =
      options.unprotectedHeaders instanceof UnprotectedHeaders
        ? options.unprotectedHeaders
        : options.unprotectedHeaders
          ? UnprotectedHeaders.fromDecodedStructure(options.unprotectedHeaders)
          : UnprotectedHeaders.create({})

    // biome-ignore lint/complexity/noThisInStatic: this.create is intentional for subclass support
    const sign1 = new this({
      protectedHeaders,
      unprotectedHeaders,
      payload: options.payload,
      signature: new Uint8Array(),
    })

    sign1.externalAad = options.externalAad

    return sign1
  }

  public async sign(
    options: {
      externalAad?: Uint8Array
      signingKey: CoseKey
      algorithm?: SignatureAlgorithm
      detachedPayload?: Uint8Array
    },
    ctx: Pick<Sign1Context, 'sign'>
  ) {
    const embeddedPayload = this.payload
    const { detachedPayload } = options

    if (embeddedPayload && detachedPayload) {
      throw new Error('Cannot provide detachedPayload when the Sign1 already contains an embedded payload')
    }

    const payload = embeddedPayload ?? detachedPayload
    if (!payload) {
      throw new CosePayloadMustBeDefinedError()
    }

    const signatureAlgorithm = options.algorithm ?? options.signingKey.algorithm

    if (!signatureAlgorithm) {
      throw new CoseInvalidAlgorithmError(
        'Could not establish signature algorithm. Either provide it in the options directly, or provide it in the signingKey'
      )
    }

    this.structure.signature = await ctx.sign({
      toBeSigned: Sign1.toBeSigned({
        payload,
        protectedHeaders: this.protectedHeaders,
        externalAad: options.externalAad,
      }),
      key: options.signingKey,
      algorithm: signatureAlgorithm,
    })

    return this
  }
}

addExtension({
  Class: Sign1,
  tag: Sign1.tag,
  encode(instance: Sign1, encodeFn: (obj: unknown) => Uint8Array) {
    return encodeFn(instance)
  },
  decode: (encoded) => Sign1.fromEncodedStructure(encoded as Sign1EncodedStructure),
})
