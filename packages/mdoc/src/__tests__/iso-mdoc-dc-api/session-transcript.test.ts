import { cborDecode } from '@owf/cose'
import { hex } from '@owf/identity-common'
import { describe, expect, test } from 'vitest'
import { IsoMdocDcApiHandover, SessionTranscript } from '../..'
import { mdocContext } from '../context'

const origin = 'https://verifier.example.com'

// A fixed base64url EncryptionInfo. The exact bytes it decodes to are irrelevant here: C.5 hashes
// the base64url *text string*, not the CBOR it encodes.
const encryptionInfoBase64Url = 'gmVkY2FwaaJlbm9uY2VQAAECAwQFBgcICQoLDA0OD3JyZWNpcGllbnRQdWJsaWNLZXmkAQIgASFYIA'

// SHA-256(CBOR([encryptionInfoBase64Url, origin])) — pinned so a change to what gets hashed
// (raw bytes instead of the base64url string, or a different array shape) is caught here rather
// than in interop testing.
const expectedHandoverInfoHash = 'b1d05b3cc73cfcc4ad210f14dc039258ba01a46832e929c0b336845c59f56c92'

describe('ISO 18013-7 Annex C session transcript', () => {
  test('handover info hash is over the base64url string, not the raw CBOR', async () => {
    const handover = await IsoMdocDcApiHandover.create({ encryptionInfoBase64Url, origin }, mdocContext)

    expect(hex.encode(handover.decodedStructure)).toBe(expectedHandoverInfoHash)
  })

  test('session transcript is [null, null, ["dcapi", hash]]', async () => {
    const sessionTranscript = await SessionTranscript.forIsoMdocDcApi({ encryptionInfoBase64Url, origin }, mdocContext)

    const raw = cborDecode<[null, null, [string, Uint8Array]]>(sessionTranscript.encode())

    expect(raw[0]).toBeNull()
    expect(raw[1]).toBeNull()
    expect(raw[2][0]).toBe('dcapi')
    expect(hex.encode(raw[2][1])).toBe(expectedHandoverInfoHash)
  })

  test('HPKE info is the bare transcript array, not SessionTranscriptBytes', async () => {
    const sessionTranscript = await SessionTranscript.forIsoMdocDcApi({ encryptionInfoBase64Url, origin }, mdocContext)

    const bare = sessionTranscript.encode()
    const asDataItem = sessionTranscript.encode({ asDataItem: true })

    // A bare 3-element array starts with 0x83; tag 24 (SessionTranscriptBytes) starts with 0xd818.
    expect(bare[0]).toBe(0x83)
    expect(asDataItem[0]).toBe(0xd8)
    expect(asDataItem[1]).toBe(0x18)
  })

  test('a different origin produces a different transcript', async () => {
    const first = await SessionTranscript.forIsoMdocDcApi({ encryptionInfoBase64Url, origin }, mdocContext)
    const second = await SessionTranscript.forIsoMdocDcApi(
      { encryptionInfoBase64Url, origin: 'https://other.example.com' },
      mdocContext
    )

    expect(hex.encode(first.encode())).not.toBe(hex.encode(second.encode()))
  })
})
