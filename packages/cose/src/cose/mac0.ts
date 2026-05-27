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
import { type MacAlgorithm, RegisteredCwtHeaderClaimKey } from './headers/defaults'
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

export const mac0EncodedSchema = z.tuple([
  zUint8Array,
  z.map(z.unknown(), z.unknown()),
  zUint8Array.nullable(),
  zUint8Array,
])

export const mac0DecodedSchema = z.object({
  protectedHeaders: z.instanceof(ProtectedHeaders),
  unprotectedHeaders: z.instanceof(UnprotectedHeaders),
  payload: zUint8Array.nullable(),
  tag: zUint8Array,
})

export type Mac0EncodedStructure = z.infer<typeof mac0EncodedSchema>
export type Mac0DecodedStructure = z.infer<typeof mac0DecodedSchema>

export type Mac0Context = {
  authenticate: (options: { toBeAuthenticated: Uint8Array; key: CoseKey | Uint8Array }) => Promise<Uint8Array>
  verify: (options: { mac0: Mac0; key: CoseKey | Uint8Array }) => Promise<boolean>
}

export type Mac0Options = {
  protectedHeaders?: ProtectedHeaders | ProtectedHeaderOptions['protectedHeaders']
  unprotectedHeaders?: UnprotectedHeaders | UnprotectedHeaderOptions['unprotectedHeaders']
  externalAad?: Uint8Array

  payload?: Uint8Array | null
  detachedPayload?: Uint8Array
}

export class Mac0 extends CborStructure<Mac0EncodedStructure, Mac0DecodedStructure> {
  public static tag = 17
  protected override _tag = Mac0.tag

  public static override get encodingSchema() {
    return z.codec(mac0EncodedSchema, mac0DecodedSchema, {
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

  public externalAad?: Uint8Array
  public detachedPayload?: Uint8Array

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

  public get toBeAuthenticated() {
    const payload = this.payload ?? this.detachedPayload

    if (!payload) {
      throw new CosePayloadMustBeDefinedError()
    }

    return Mac0.toBeAuthenticated({
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
      // NOTE: If decoded with Mac0 tag, the cbor decoder already transforms to the class instances
      // In that case we create new instance based on the decoded structure, to ensure we create the
      // instance based on this (and ensure extended classes work)
      rawStructure instanceof Mac0
        ? rawStructure.decodedStructure
        : Mac0.fromEncodedStructure(rawStructure as EncodedStructureType<T>).decodedStructure
    ) as unknown as T
  }

  public static toBeAuthenticated(options: {
    payload: Uint8Array
    protectedHeaders: ProtectedHeaders
    externalAad?: Uint8Array
  }) {
    const toBeAuthenticated = ['MAC0', options.protectedHeaders.encodedStructure]
    if (options.externalAad) toBeAuthenticated.push(options.externalAad)
    toBeAuthenticated.push(options.payload)

    return cborEncode(toBeAuthenticated)
  }

  public get signatureAlgorithmName(): MacAlgorithm {
    const algorithm = (this.protectedHeaders.headers?.get(RegisteredCwtHeaderClaimKey.Algorithm) ??
      this.unprotectedHeaders.headers?.get(RegisteredCwtHeaderClaimKey.Algorithm)) as MacAlgorithm | undefined

    if (!algorithm) {
      throw new CoseInvalidAlgorithmError()
    }

    const algorithmName = coseKeyToJwkClaim.algorithm(algorithm)

    if (!algorithmName) {
      throw new CoseInvalidAlgorithmError()
    }

    return algorithmName
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

    const payload = options.payload ?? options.detachedPayload
    if (!payload) {
      throw new CosePayloadMustBeDefinedError()
    }

    // biome-ignore lint/complexity/noThisInStatic: this.create is intentional for subclass support
    const mac0 = new this({
      protectedHeaders,
      unprotectedHeaders,
      payload: options.payload ?? null,
      tag: new Uint8Array(),
    })

    mac0.externalAad = options.externalAad
    mac0.detachedPayload = options.detachedPayload

    return mac0
  }

  public async authenticate(
    options: {
      key: CoseKey | Uint8Array
    },
    ctx: Pick<Mac0Context, 'authenticate'>
  ) {
    const payload = this.payload ?? this.detachedPayload
    if (!payload) {
      throw new CosePayloadMustBeDefinedError()
    }

    this.structure.tag = await ctx.authenticate({
      toBeAuthenticated: Mac0.toBeAuthenticated({
        payload,
        protectedHeaders: this.protectedHeaders,
        externalAad: this.externalAad,
      }),
      key: options.key,
    })
    return this
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
