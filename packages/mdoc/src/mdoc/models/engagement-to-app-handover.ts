import { zUint8Array } from '@owf/cose'
import type z from 'zod'
import { Handover } from './handover'

const engagementToAppHandoverSchema = zUint8Array
export type EngagementToAppHandoverStructure = z.infer<typeof engagementToAppHandoverSchema>

/**
 * The handover of ISO/IEC TS 18013-7 Annex A, device retrieval to a website.
 *
 * A.8 defines it as a bare byte string:
 *
 *   Handover = EngagementToApp / any
 *   EngagementToApp = ReaderEngagementBytesHash
 *   ReaderEngagementBytesHash = bstr
 *   ReaderEngagementBytes = #6.24(bstr .cbor ReaderEngagement)
 *
 * where the hash is SHA-256 of ReaderEngagementBytes. Computing it is the
 * caller's business, since only the reader and the mdoc hold the
 * ReaderEngagement; this class is the CBOR shape.
 *
 * It is the only handover that is not a tuple or null, so it can never be
 * confused with one of the others when a SessionTranscript is decoded.
 */
export class EngagementToAppHandover extends Handover<EngagementToAppHandoverStructure> {
  public static override get encodingSchema() {
    return engagementToAppHandoverSchema
  }

  public get readerEngagementBytesHash() {
    return this.structure
  }

  public override get requiresReaderKey() {
    return true
  }

  public override get requiresDeviceEngagement() {
    return true
  }

  public static create(readerEngagementBytesHash: Uint8Array) {
    // biome-ignore lint/complexity/noThisInStatic: this.fromDecodedStructure is intentional for subclass support
    return this.fromDecodedStructure(readerEngagementBytesHash)
  }
}
