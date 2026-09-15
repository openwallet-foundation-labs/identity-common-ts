import {
  type AnyCborStructure,
  type CborEncodeOptions,
  CborStructure,
  type CborStructureStaticThis,
  cborEncode,
  DataItem,
  TypedMap,
} from '@owf/cose'
import { unwrapDataItemBytes } from '../utils/cbor'

/**
 * A CBOR structure that keeps the bytes it was decoded from, and encodes with them until it is
 * modified.
 *
 * ISO/IEC 18013-5 8.1: "the bytestrings shall be used as they are sent or received". Structures that
 * are embedded as bytes in a signed, MACed or hashed structure are therefore embedded as received, as
 * re-encoding the decoded structure may give other bytes, for instance for floats, tag 0 dates with
 * fractional seconds, indefinite lengths or non-shortest encodings of another encoder.
 *
 * The bytes are kept when the structure is decoded with {@link decode} or {@link fromDataItem}, so a
 * parent structure has to decode it from its data item with `fromDataItem`, and embed it with
 * {@link asDataItem}.
 *
 * Setting or deleting an entry of a structure that is a `TypedMap` drops the bytes on its own. Call
 * {@link markModified} after changing the structure in any other way, such as a nested value.
 */
export class OriginalBytesCborStructure<
  EncodedStructure = unknown,
  DecodedStructure = EncodedStructure,
> extends CborStructure<EncodedStructure, DecodedStructure> {
  #originalBytes?: Uint8Array

  public constructor(structure: DecodedStructure) {
    super(structure)

    if (structure instanceof TypedMap) {
      structure.onChange = () => this.markModified()
    }
  }

  /**
   * The bytes this structure was decoded from, without tag 24, if it was decoded and has not been
   * modified since.
   */
  public get originalBytes() {
    return this.#originalBytes
  }

  /**
   * Drops the {@link originalBytes}, so that the structure is re-encoded the next time it is encoded.
   */
  public markModified() {
    this.#originalBytes = undefined
  }

  /**
   * Accepts the encoded structure as well as the structure wrapped in tag 24.
   */
  public static override decode<T extends AnyCborStructure>(this: CborStructureStaticThis<T>, bytes: Uint8Array): T {
    // biome-ignore lint/complexity/noThisInStatic: `super.decode` keeps `this` bound to the subclass
    const structure = super.decode(bytes) as T

    if (structure instanceof OriginalBytesCborStructure) {
      structure.#originalBytes = unwrapDataItemBytes(bytes)
    }

    return structure
  }

  public static override fromDataItem<T extends AnyCborStructure>(
    this: CborStructureStaticThis<T>,
    dataItem: unknown
  ): T {
    // biome-ignore lint/complexity/noThisInStatic: `super.fromDataItem` keeps `this` bound to the subclass
    const structure = super.fromDataItem(dataItem) as T

    if (structure instanceof OriginalBytesCborStructure && dataItem instanceof DataItem) {
      structure.#originalBytes = new Uint8Array(dataItem.buffer)
    }

    return structure
  }

  public override encode(options?: CborEncodeOptions): Uint8Array {
    if (!this.#originalBytes) return super.encode(options)

    return options?.asDataItem ? cborEncode(this.asDataItem) : this.#originalBytes
  }

  /**
   * This structure as a tag 24 data item, with the bytes it was received as if it was decoded.
   */
  public get asDataItem(): DataItem<EncodedStructure> {
    return DataItem.fromBuffer<EncodedStructure>(this.encode())
  }
}
