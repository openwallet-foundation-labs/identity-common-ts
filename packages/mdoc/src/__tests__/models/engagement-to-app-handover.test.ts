import { cborDecode, cborEncode, DataItem } from '@owf/cose'
import { hex } from '@owf/identity-common'
import { describe, expect, test } from 'vitest'
import { DeviceEngagement } from '../../mdoc/models/device-engagement'
import { EReaderKey } from '../../mdoc/models/e-reader-key'
import { EngagementToAppHandover } from '../../mdoc/models/engagement-to-app-handover'
import { NfcHandover } from '../../mdoc/models/nfc-handover'
import { QrHandover } from '../../mdoc/models/qr-handover'
import { SessionTranscript } from '../../mdoc/models/session-transcript'

// D.3.1 of ISO/IEC 18013-5, reused by the session transcript test next door.
const deviceEngagement =
  'a20063312e30018201d818584ba4010220012158205a88d182bce5f42efa59943f33359d2e8a968ff289d93e5fa444b624343167fe225820b16e8cf858ddc7690407ba61d4c338237a8cfcf3de6aa672fc60a557aa32fc67'
const eReaderKey =
  'a40102200121582060e3392385041f51403051f2415531cb56dd3f999c71687013aac6768bc8187e225820e58deb8fdbe907f7dd5368245551a34796f7d2215c440c339bb0f7b67beccdfa'

// Any 32 bytes; A.8 only says SHA-256 of ReaderEngagementBytes.
const readerEngagementBytesHash = hex.decode('9b4a1c1f4e9f6f0f2a3d5c7e8f0a1b2c3d4e5f60718293a4b5c6d7e8f9a0b1c2')

describe('EngagementToApp handover (ISO/IEC TS 18013-7 Annex A)', () => {
  test('encodes as the bare byte string A.8 defines', () => {
    const handover = EngagementToAppHandover.create(readerEngagementBytesHash)

    expect(handover.readerEngagementBytesHash).toEqual(readerEngagementBytesHash)
    // A bstr, not a tuple and not a tagged value.
    expect(cborDecode(handover.encode())).toEqual(readerEngagementBytesHash)
  })

  test('round-trips through a session transcript', () => {
    const transcript = SessionTranscript.forEngagementToApp({
      deviceEngagement: DeviceEngagement.decode(hex.decode(deviceEngagement)),
      eReaderKey: EReaderKey.decode(hex.decode(eReaderKey)),
      readerEngagementBytesHash,
    })

    const decoded = SessionTranscript.decode(transcript.encode())

    expect(decoded.handover).toBeInstanceOf(EngagementToAppHandover)
    expect((decoded.handover as EngagementToAppHandover).readerEngagementBytesHash).toEqual(readerEngagementBytesHash)
    expect(decoded.deviceEngagement).toBeInstanceOf(DeviceEngagement)
    expect(decoded.eReaderKey).toBeInstanceOf(EReaderKey)
  })

  test('preserves the engagement bytes the session keys are derived from', () => {
    // Annex A keeps ISO 18013-5 session encryption, whose salt is
    // SHA-256(SessionTranscriptBytes), so a byte that moves here moves
    // the keys with it.
    const transcript = SessionTranscript.forEngagementToApp({
      deviceEngagement: DeviceEngagement.decode(hex.decode(deviceEngagement)),
      eReaderKey: EReaderKey.decode(hex.decode(eReaderKey)),
      readerEngagementBytesHash,
    })

    const [engagement, reader, handover] = cborDecode(transcript.encode()) as [DataItem, DataItem, Uint8Array]

    expect(hex.encode(engagement.buffer)).toEqual(deviceEngagement)
    expect(hex.encode(reader.buffer)).toEqual(eReaderKey)
    expect(handover).toEqual(readerEngagementBytesHash)
  })

  test('is not confused with the other handovers, nor they with it', () => {
    // Every other handover is a tuple or null, so decoding is
    // unambiguous in both directions. This is what makes it safe to add
    // a schema as loose as `bstr` to the discrimination list.
    const asBstr = SessionTranscript.forEngagementToApp({
      deviceEngagement: DeviceEngagement.decode(hex.decode(deviceEngagement)),
      eReaderKey: EReaderKey.decode(hex.decode(eReaderKey)),
      readerEngagementBytesHash,
    })
    expect(SessionTranscript.decode(asBstr.encode()).handover).toBeInstanceOf(EngagementToAppHandover)

    const asQr = SessionTranscript.forQrHandover({
      deviceEngagement: DeviceEngagement.decode(hex.decode(deviceEngagement)),
      eReaderKey: EReaderKey.decode(hex.decode(eReaderKey)),
    })
    expect(SessionTranscript.decode(asQr.encode()).handover).toBeInstanceOf(QrHandover)

    const asNfc = SessionTranscript.create({
      deviceEngagement: DeviceEngagement.decode(hex.decode(deviceEngagement)),
      eReaderKey: EReaderKey.decode(hex.decode(eReaderKey)),
      handover: NfcHandover.create({ selectMessage: readerEngagementBytesHash }),
    })
    expect(SessionTranscript.decode(asNfc.encode()).handover).toBeInstanceOf(NfcHandover)
  })

  test('accepts a transcript assembled by hand, as a remote reader sends it', () => {
    const byHand = cborEncode([
      new DataItem({ buffer: hex.decode(deviceEngagement) }),
      new DataItem({ buffer: hex.decode(eReaderKey) }),
      readerEngagementBytesHash,
    ])

    const decoded = SessionTranscript.decode(byHand)
    expect(decoded.handover).toBeInstanceOf(EngagementToAppHandover)
    expect(hex.encode(decoded.encode())).toEqual(hex.encode(byHand))
  })
})
