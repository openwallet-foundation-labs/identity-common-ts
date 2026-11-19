import { z } from 'zod'
import {
  type AnyCborStructure,
  addExtension,
  CborStructure,
  type CborStructureStaticThis,
  cborDecode,
  cborEncode,
  type EncodedStructureType,
} from '../cbor'
import { zUint8Array } from '../utils/zod'
import { CoseInvalidAlgorithmError, CosePayloadMustBeDefinedError } from './error'
import { MacAlgorithm, RegisteredCwtHeaderClaimKey } from './headers/defaults'
import {
  type ProtectedHeaderOptions,
  ProtectedHeaders,
  type ProtectedHeadersEncodedStructure,
} from './headers/protected-headers'
import {
  type UnprotectedHeaderOptions,
  UnprotectedHeaders,
  type UnprotectedHeadersStructure,
} from './headers/unprotected-headers'
import type { CoseKey } from './key'
import { coseKeyToJwkClaim } from './key/jwk'

export const zMac0Encoded = z.tuple([zUint8Array, z.map(z.unknown(), z.unknown()), zUint8Array.nullable(), zUint8Array])

export const zMac0Decoded = z.object({
  protectedHeaders: z.instanceof(ProtectedHeaders),
  unprotectedHeaders: z.instanceof(UnprotectedHeaders),
  payload: zUint8Array.nullable(),
  tag: zUint8Array,
})

export type Mac0EncodedStructure = z.infer<typeof zMac0Encoded>
export type Mac0DecodedStructure = z.infer<typeof zMac0Decoded>

export type Mac0Context = {
  authenticate: (options: {
    toBeAuthenticated: Uint8Array
    key: CoseKey
    algorithm: MacAlgorithm
  }) => Promise<Uint8Array>
  verify: (options: {
    toBeAuthenticated: Uint8Array
    tag: Uint8Array
    key: CoseKey
    algorithm?: MacAlgorithm
  }) => Promise<boolean>
}

export type Mac0Options = {
  protectedHeaders?: ProtectedHeaders | ProtectedHeaderOptions['protectedHeaders']
  unprotectedHeaders?: UnprotectedHeaders | UnprotectedHeaderOptions['unprotectedHeaders']

  /**
   * The embedded payload. Pass `null` to explicitly signal a detached payload
   * (the encoded structure will contain null, and you must supply the payload
   * via `detachedPayload` when calling `authenticate()` / `toBeAuthenticated()`).
   */
  payload: Uint8Array | null

  tag?: Uint8Array
}

export class Mac0 extends CborStructure<Mac0EncodedStructure, Mac0DecodedStructure> {
  public static tag = 17
  protected override _tag = Mac0.tag

  public static override get encodingSchema() {
    return z.codec(zMac0Encoded, zMac0Decoded, {
      encode: ({ protectedHeaders, unprotectedHeaders, payload, tag }) => {
        if (tag.length === 0) {
          throw new Error('Tag has not been set. Required for encoding the mac0 structure')
        }
        return [
          protectedHeaders.encodedStructure,
          unprotectedHeaders.encodedStructure,
          payload,
          tag,
        ] satisfies Mac0EncodedStructure
      },
      decode: ([protectedHeadersBytes, unprotectedHeadersMap, payload, tag]) => ({
        protectedHeaders: ProtectedHeaders.fromEncodedStructure(
          protectedHeadersBytes as ProtectedHeadersEncodedStructure
        ),
        unprotectedHeaders: UnprotectedHeaders.fromEncodedStructure(
          unprotectedHeadersMap as UnprotectedHeadersStructure
        ),
        payload,
        tag,
      }),
    })
  }

  public get protectedHeaders() {
    return this.structure.protectedHeaders
  }

  public get unprotectedHeaders() {
    return this.structure.unprotectedHeaders
  }

  public get payload() {
    return this.structure.payload
  }

  public get tag() {
    return this.structure.tag
  }

  /**
   * Returns the MAC_Structure bytes that are authenticated/verified.
   *
   * @param options.detachedPayload - The detached payload to use. Must be provided when
   *   the Mac0 was created with a detached payload (i.e. `payload` field is null).
   *   Cannot be provided when the Mac0 already contains an embedded payload.
   * @param options.externalAad - Externally supplied data covered by the authentication tag. It is
   *   not part of the COSE structure, so it has to be provided identically wherever the
   *   MAC_Structure is built: `authenticate()`, `verifyAuthenticationCode()` and here.
   */
  public toBeAuthenticated(options?: { detachedPayload?: Uint8Array; externalAad?: Uint8Array }): Uint8Array {
    const embeddedPayload = this.payload
    const detachedPayload = options?.detachedPayload

    if (embeddedPayload && detachedPayload) {
      throw new Error('Cannot provide detachedPayload when the Mac0 already contains an embedded payload')
    }

    const payload = embeddedPayload ?? detachedPayload
    if (!payload) {
      throw new CosePayloadMustBeDefinedError()
    }

    return Mac0.toBeAuthenticated({
      payload,
      protectedHeaders: this.protectedHeaders,
      externalAad: options?.externalAad,
    })
  }

  /**
   * The MAC_structure that earlier versions of this library built without `external_aad`, so their
   * tags still verify. Call only after {@link toBeAuthenticated}, which checks the payload.
   */
  protected legacyToBeAuthenticated(options?: { detachedPayload?: Uint8Array }): Uint8Array {
    return cborEncode(['MAC0', this.protectedHeaders.encodedStructure, this.payload ?? options?.detachedPayload])
  }

  /**
   * Decodes CBOR bytes into a Mac0 instance.
   * Uses the encodingSchema's decode() method to validate and transform the decoded data.
   */
  public static decode<T extends AnyCborStructure>(this: CborStructureStaticThis<T>, bytes: Uint8Array): T {
    const rawStructure = cborDecode(bytes)

    // May feel weird, but using new this makes TypeScript understand we may return a subclass
    return new this(
      // NOTE: If decoded with Mac0 tag, the cbor decoder already transforms to the class instances
      // In that case we create new instance based on the decoded structure, to ensure we create the
      // instance based on this (and ensure extended classes work)
      // biome-ignore lint/complexity/noThisInStatic: this check is intentional for subclass support
      rawStructure instanceof Mac0 && rawStructure.constructor === this
        ? rawStructure.decodedStructure
        : // biome-ignore lint/complexity/noThisInStatic: this.fromEncodedStructure is intentional for subclass support
          this.fromEncodedStructure(
            (rawStructure instanceof Mac0 ? rawStructure.encodedStructure : rawStructure) as EncodedStructureType<T>
          ).decodedStructure
    ) as unknown as T
  }

  public static toBeAuthenticated(options: {
    payload: Uint8Array
    protectedHeaders: ProtectedHeaders
    externalAad?: Uint8Array
  }) {
    // RFC 9052 6.3: external_aad is always part of the MAC_structure, a zero-length bstr when not supplied.
    return cborEncode([
      'MAC0',
      options.protectedHeaders.encodedStructure,
      options.externalAad ?? new Uint8Array(),
      options.payload,
    ])
  }

  public get algorithm(): MacAlgorithm | undefined {
    const algorithm = this.protectedHeaders.headers?.get(RegisteredCwtHeaderClaimKey.Algorithm) as
      | MacAlgorithm
      | undefined
    if (algorithm && !Object.values(MacAlgorithm).includes(algorithm)) {
      throw new CoseInvalidAlgorithmError()
    }

    return algorithm
  }

  public get jwaAlgorithm(): keyof typeof MacAlgorithm {
    const alg = this.algorithm

    const jwaAlg = coseKeyToJwkClaim.algorithm(alg)
    if (!jwaAlg) {
      throw new CoseInvalidAlgorithmError(`Cose algorithm ${alg} does not have a corresponding JWA alg`)
    }

    return jwaAlg
  }

  public static create(options: Mac0Options): Mac0 {
    const protectedHeaders =
      options.protectedHeaders instanceof ProtectedHeaders
        ? options.protectedHeaders
        : ProtectedHeaders.create({ protectedHeaders: options.protectedHeaders })

    const unprotectedHeaders =
      options.unprotectedHeaders instanceof UnprotectedHeaders
        ? options.unprotectedHeaders
        : UnprotectedHeaders.create({ unprotectedHeaders: options.unprotectedHeaders })

    const mac0 = new this({
      protectedHeaders,
      unprotectedHeaders,
      payload: options.payload,
      tag: options.tag ?? new Uint8Array(),
    })

    return mac0
  }

  public async authenticate(
    options: {
      key: CoseKey
      detachedPayload?: Uint8Array
      algorithm?: MacAlgorithm
      externalAad?: Uint8Array
    },
    ctx: Pick<Mac0Context, 'authenticate'>
  ) {
    const embeddedPayload = this.payload
    const { detachedPayload } = options

    if (embeddedPayload && detachedPayload) {
      throw new Error('Cannot provide detachedPayload when the Mac0 already contains an embedded payload')
    }

    const payload = embeddedPayload ?? detachedPayload
    if (!payload) {
      throw new CosePayloadMustBeDefinedError()
    }

    const macAlgorithm = options.algorithm ?? (options.key.algorithm as MacAlgorithm | undefined)

    if (!macAlgorithm) {
      throw new CoseInvalidAlgorithmError(
        'Could not establish mac algorithm. Either provide it in the options directly, or provide it in the key'
      )
    }

    if (!Object.values(MacAlgorithm).includes(macAlgorithm as MacAlgorithm)) {
      throw new CoseInvalidAlgorithmError('Invalid mac algorithm.')
    }

    this.structure.tag = await ctx.authenticate({
      toBeAuthenticated: Mac0.toBeAuthenticated({
        payload,
        protectedHeaders: this.protectedHeaders,
        externalAad: options.externalAad,
      }),
      algorithm: macAlgorithm,
      key: options.key,
    })
    return this
  }

  public async verifyAuthenticationCode(
    { key, detachedPayload, externalAad }: { key: CoseKey; detachedPayload?: Uint8Array; externalAad?: Uint8Array },
    ctx: Pick<Mac0Context, 'verify'>
  ) {
    const embeddedPayload = this.payload
    if (embeddedPayload && detachedPayload) {
      throw new Error('Cannot provide detachedPayload when the Mac0 already contains an embedded payload')
    }

    const verify = (toBeAuthenticated: Uint8Array) =>
      ctx.verify({ key, tag: this.tag, toBeAuthenticated, algorithm: this.algorithm })

    if (await verify(this.toBeAuthenticated({ detachedPayload, externalAad }))) return true
    if (externalAad !== undefined) return false

    return await verify(this.legacyToBeAuthenticated({ detachedPayload }))
  }
}

addExtension({
  Class: Mac0,
  tag: Mac0.tag,
  encode(instance: Mac0, encodeFn: (obj: unknown) => Uint8Array) {
    return encodeFn(instance)
  },
  decode: (encoded) => Mac0.fromEncodedStructure(encoded as Mac0EncodedStructure),
})
