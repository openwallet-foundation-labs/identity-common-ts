import { describe, expect, test } from 'vitest'
import { EDeviceKey, EReaderKey, SessionTranscript } from '../..'
import { SessionEstablishment } from '../../mdoc/models/session-establishment'
import { DEVICE_JWK_PRIVATE, DEVICE_JWK_PUBLIC } from '../config'
import { mdocContext } from '../context'

describe('session establishment', () => {
  test('SKReader is derived with SHA-256 of the SessionTranscriptBytes as salt (9.1.1.5)', async () => {
    const sessionTranscript = await SessionTranscript.forIsoMdocDcApi(
      { encryptionInfoBase64Url: 'abc', origin: 'https://verifier.example.com' },
      mdocContext
    )

    const salts: Array<Uint8Array> = []
    const ctx = {
      crypto: {
        ...mdocContext.crypto,
        hdkf: async (options: Parameters<typeof mdocContext.crypto.hdkf>[0]) => {
          salts.push(options.salt)
          return new Uint8Array(32)
        },
      },
    }

    const sessionEstablishment = SessionEstablishment.create({
      eReaderKey: EReaderKey.fromJwk(DEVICE_JWK_PUBLIC),
      data: new Uint8Array(),
    })

    // Decryption itself is not implemented yet.
    await expect(
      sessionEstablishment.decryptedData(
        {
          eDeviceKeyPrivate: EDeviceKey.fromJwk(DEVICE_JWK_PRIVATE),
          eReaderKeyPublic: EReaderKey.fromJwk(DEVICE_JWK_PUBLIC),
          sessionTranscript,
        },
        ctx
      )
    ).rejects.toThrow('unimplemented')

    const expectedSalt = await mdocContext.crypto.digest({
      digestAlgorithm: 'SHA-256',
      bytes: sessionTranscript.encode({ asDataItem: true }),
    })
    expect(salts).toStrictEqual([expectedSalt])
  })
})
