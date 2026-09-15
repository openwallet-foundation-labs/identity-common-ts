import {
  type AnyCborStructure,
  type CborEncodeOptions,
  type CborStructureStaticThis,
  CoseKey,
  type CoseKeyDecodedStructure,
  type CoseKeyEncodedStructure,
  type CoseKeyOptions,
  cborEncode,
  DataItem,
} from '@owf/cose'
import { unwrapDataItemBytes } from '../../utils/cbor'

export type EReaderKeyDecodedStructure = CoseKeyDecodedStructure
export type EReaderKeyEncodedStructure = CoseKeyEncodedStructure
export type EReaderKeyOptions = CoseKeyOptions

/**
 * A `CoseKey` for the ephemeral key of the mdoc reader, which keeps the bytes it was decoded from the
 * way `OriginalBytesCborStructure` does, as `EReaderKeyBytes` are part of the session transcript
 * (18013-5 8.1). It extends `CoseKey`, so it cannot extend `OriginalBytesCborStructure`.
 */
export class EReaderKey extends CoseKey {
  #originalBytes?: Uint8Array

  public static override create(options: EReaderKeyOptions): EReaderKey {
    // biome-ignore lint/complexity/noThisInStatic: `super.create` keeps `this` bound to the subclass
    return super.create(options) as EReaderKey
  }

  public static override fromJwk(jwk: Record<string, unknown>): EReaderKey {
    // biome-ignore lint/complexity/noThisInStatic: `super.fromJwk` keeps `this` bound to the subclass
    return super.fromJwk(jwk) as EReaderKey
  }

  /**
   * The bytes this reader key was decoded from, if it was decoded. A decoded reader key encodes as it
   * was received, as `EReaderKeyBytes` are part of the session transcript (18013-5 8.1).
   */
  public get originalBytes() {
    return this.#originalBytes
  }

  public static override decode<T extends AnyCborStructure>(this: CborStructureStaticThis<T>, bytes: Uint8Array): T {
    // biome-ignore lint/complexity/noThisInStatic: `super.decode` keeps `this` bound to the subclass
    const eReaderKey = super.decode(bytes) as unknown as T
    if (eReaderKey instanceof EReaderKey) eReaderKey.#originalBytes = unwrapDataItemBytes(bytes)
    return eReaderKey
  }

  public static override fromDataItem<T extends AnyCborStructure>(
    this: CborStructureStaticThis<T>,
    dataItem: unknown
  ): T {
    // biome-ignore lint/complexity/noThisInStatic: `super.fromDataItem` keeps `this` bound to the subclass
    const eReaderKey = super.fromDataItem(dataItem) as unknown as T
    if (eReaderKey instanceof EReaderKey && dataItem instanceof DataItem) {
      eReaderKey.#originalBytes = new Uint8Array(dataItem.buffer)
    }
    return eReaderKey
  }

  public override encode(options?: CborEncodeOptions): Uint8Array {
    if (!this.#originalBytes) return super.encode(options)
    return options?.asDataItem ? cborEncode(this.asDataItem) : this.#originalBytes
  }

  /**
   * This reader key as a tag 24 data item, with the bytes it was received as if it was decoded.
   */
  public get asDataItem(): DataItem<EReaderKeyEncodedStructure> {
    return DataItem.fromBuffer<EReaderKeyEncodedStructure>(this.encode())
  }
}
