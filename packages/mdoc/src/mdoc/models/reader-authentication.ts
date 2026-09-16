import { CborStructure, DataItem } from '@owf/cose'
import { z } from 'zod'
import { ItemsRequest, type ItemsRequestEncodedStructure } from './items-request'
import { SessionTranscript, sessionTranscriptEncodedSchema } from './session-transcript'

const readerAuthenticationEncodedSchema = z.tuple([
  z.literal('ReaderAuthentication'),
  sessionTranscriptEncodedSchema,
  z.instanceof<typeof DataItem<ItemsRequestEncodedStructure>>(DataItem),
])

const readerAuthenticationDecodedSchema = z.object({
  sessionTranscript: z.instanceof(SessionTranscript),
  itemsRequest: z.instanceof(ItemsRequest),
})

export type ReaderAuthenticationDecodedStructure = z.infer<typeof readerAuthenticationDecodedSchema>
export type ReaderAuthenticationEncodedStructure = z.infer<typeof readerAuthenticationEncodedSchema>

export type ReaderAuthenticationOptions = {
  sessionTranscript: SessionTranscript
  itemsRequest: ItemsRequest
}

export class ReaderAuthentication extends CborStructure<
  ReaderAuthenticationEncodedStructure,
  ReaderAuthenticationDecodedStructure
> {
  public static override get encodingSchema() {
    return z.codec(readerAuthenticationEncodedSchema, readerAuthenticationDecodedSchema, {
      decode: ([, sessionTranscript, itemsRequestDataItem]) => ({
        sessionTranscript: SessionTranscript.fromEncodedStructure(sessionTranscript),
        itemsRequest: ItemsRequest.fromDataItem(itemsRequestDataItem),
      }),
      encode: ({ sessionTranscript, itemsRequest }) =>
        [
          'ReaderAuthentication',
          sessionTranscript.encodedStructure,
          // `ItemsRequestBytes` are signed as the mdoc reader sent them (18013-5 8.1).
          itemsRequest.asDataItem,
        ] satisfies ReaderAuthenticationEncodedStructure,
    })
  }

  public get sessionTranscript() {
    return this.structure.sessionTranscript
  }

  public get itemsRequest() {
    return this.structure.itemsRequest
  }

  public static create(options: ReaderAuthenticationOptions): ReaderAuthentication {
    // biome-ignore lint/complexity/noThisInStatic: this.fromDecodedStructure is intentional for subclass support
    return this.fromDecodedStructure({
      sessionTranscript: options.sessionTranscript,
      itemsRequest: options.itemsRequest,
    })
  }
}
