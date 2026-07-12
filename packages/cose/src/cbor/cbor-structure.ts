// biome-ignore-all lint: @biomejs/biome seems to change the `new this(...)` calls into `new CborStructure(...)` which seems to cause a bug for this specific use case. We cannot alias to `thiz` or disable a specific rule

import { Tag } from 'cbor-x'
import { z } from 'zod'
import {
  decodeStructureWithErrorHandling,
  encodeStructureWithErrorHandling,
  parseStructureWithErrorHandling,
} from '../utils/zod'
import { DataItem } from './data-item'
import { cborDecode, cborEncode } from './parser'

export type CborEncodeOptions = {
  asDataItem?: boolean
}

export type AnyCborStructure = CborStructure<any, any>
export type EncodedStructureType<T> = T extends CborStructure<infer EncodedStructure, unknown> ? EncodedStructure : any
export type DecodedStructureType<T> = T extends CborStructure<unknown, infer DecodedStructure> ? DecodedStructure : any

export type CborStructureStaticThis<T extends AnyCborStructure> = {
  new (structure: any): T
  encodingSchema: z.ZodType<any, any, any> | undefined
  fromEncodedStructure: (encodedStructure: EncodedStructureType<T>) => { decodedStructure: DecodedStructureType<T> }
}

export class CborStructure<EncodedStructure = unknown, DecodedStructure = EncodedStructure> {
  protected structure: DecodedStructure
  protected _tag: number | undefined

  public constructor(structure: DecodedStructure) {
    this.structure = structure
  }

  public get decodedStructure(): DecodedStructure {
    return this.structure
  }

  /**
   * Static getter for the Zod codec schema that defines the CBOR structure.
   * Subclasses CAN override this to provide their specific schema for automatic encoding/decoding.
   * The schema should be a Zod schema or codec that handles validation and transformation.
   * If not provided, subclasses must override encode(), decode(), and fromEncodedStructure().
   */
  public static get encodingSchema(): z.ZodType | undefined {
    return undefined
  }

  /**
   * Returns the encoded structure that will be serialized to CBOR.
   * By default, returns the protected structure property.
   * Override if custom encoding logic is needed.
   */
  public get encodedStructure(): EncodedStructure {
    const encodingSchema = (this.constructor as typeof CborStructure).encodingSchema
    if (!encodingSchema) {
      throw new Error('encodedStructure must be implemented when encodingSchema is not provided')
    }

    return encodeStructureWithErrorHandling(this.constructor.name, encodingSchema, this.structure) as EncodedStructure
  }

  /**
   * Encodes this structure to CBOR bytes.
   */
  public encode(options?: CborEncodeOptions): Uint8Array {
    const encodedStructure = options?.asDataItem ? DataItem.fromData(this.encodedStructure) : this.encodedStructure
    const tagged = this._tag ? new Tag(encodedStructure, this._tag) : encodedStructure

    return cborEncode(tagged)
  }

  /**
   * Decodes CBOR bytes into a structure instance.
   * Uses the encodingSchema's decode() method to validate and transform the decoded data.
   */
  public static decode<T extends AnyCborStructure>(this: CborStructureStaticThis<T>, bytes: Uint8Array): T {
    const rawStructure = cborDecode(bytes)

    // May feel weird, but using new this makes TypeScript understand we may return a subclass
    return new this(this.fromEncodedStructure(rawStructure as EncodedStructureType<T>).decodedStructure)
  }

  /**
   * Creates a structure instance from the encoded CBOR structure (after calling cborDecode).
   *
   * Uses the encodingSchema's decode() method to validate and transform the structure if available.
   * Otherwise, subclasses must override this method.
   */
  public static fromEncodedStructure<T extends AnyCborStructure>(
    this: CborStructureStaticThis<T>,
    encodedStructure: EncodedStructureType<T>
  ): T {
    if (!this.encodingSchema) {
      throw new Error('fromEncodedStructure must be implemented when encodingSchema is not provided')
    }

    return new this(decodeStructureWithErrorHandling(this.name, this.encodingSchema, encodedStructure))
  }

  public static fromDataItem<T extends AnyCborStructure>(this: CborStructureStaticThis<T>, dataItem: unknown): T {
    return new this(
      parseStructureWithErrorHandling(
        this.name,
        z
          .instanceof(DataItem)
          .transform((di) => di.data)
          .transform((d) => this.fromEncodedStructure(d as any).decodedStructure),
        dataItem,
        `Error decoding ${this.name} from DateItem`
      )
    )
  }

  /**
   * Creates a structure instance from the decoded structure.
   *
   * Uses the encodingSchema's parse method to validate the structure if available.
   * Otherwise, subclasses must override this method.
   */
  public static fromDecodedStructure<T extends AnyCborStructure>(
    this: CborStructureStaticThis<T>,
    decodedStructure: DecodedStructureType<T>
  ): T {
    const encodingSchema = this.encodingSchema
    if (!encodingSchema) {
      throw new Error('fromDecodedStructure must be implemented when encodingSchema is not provided')
    }

    // When the schema is a codec, we need to validate it against the output schema, not the input schema
    const decodedSchema = encodingSchema instanceof z.ZodPipe ? encodingSchema.out : encodingSchema

    return new this(parseStructureWithErrorHandling(this.name, decodedSchema, decodedStructure))
  }
}
