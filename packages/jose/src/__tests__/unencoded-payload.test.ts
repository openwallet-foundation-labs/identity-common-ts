import { base64url, stringToBytes } from '@owf/identity-common'
import { describe, expect, it } from 'vitest'
import { JoseInvalidArgumentError, JoseNotSupportedError, JoseParseError } from '../error'
import { parseJws } from '../jws/parse-jws'
import { signCompactJws } from '../jws/sign-jws'
import { verifyJwsSignature } from '../jws/verify-jws'
import { createEs256Context } from './context'

const unencodedHeader = { alg: 'ES256', b64: false, crit: ['b64'] }

/** Matches a thrown error by its class and a part of its message. */
const joseError = (type: { name: string }, message: string) =>
  expect.objectContaining({ name: type.name, message: expect.stringContaining(message) })
const encode = (value: unknown) => base64url.encode(stringToBytes(JSON.stringify(value)))

/**
 * RFC 7797 allows any bytes in a detached unencoded payload, but the signing input is a string here —
 * it is what the callbacks are given — so a payload that is not valid UTF-8 is reported as not
 * supported rather than with an error from outside this package.
 */
describe('an unencoded payload that is not valid UTF-8', () => {
  const binaryPayload = new Uint8Array([0xff, 0xfe, 0x00, 0x01])
  // Matched on name and message, as the error also carries the decoding error as its cause
  const notSupported = expect.objectContaining({
    name: JoseNotSupportedError.name,
    message: `An unencoded payload ('b64' is false) that is not valid UTF-8 is not supported.`,
  })

  it('is not supported as the detached payload of a JWS that is parsed', () => {
    expect(() =>
      parseJws({
        jws: `${encode(unencodedHeader)}..c2ln`,
        detachedPayload: binaryPayload,
        understoodCriticalParameters: ['b64'],
      })
    ).toThrow(notSupported)
  })

  it('keeps the decoding error as the cause', () => {
    const error = (() => {
      try {
        parseJws({
          jws: `${encode(unencodedHeader)}..c2ln`,
          detachedPayload: binaryPayload,
          understoodCriticalParameters: ['b64'],
        })
      } catch (error) {
        return error
      }
    })()

    expect(error).toMatchObject({ cause: expect.objectContaining({ message: 'Invalid UTF-8 byte sequence' }) })
  })

  it.each([false, true])('is not supported for signing, with detachPayload %s', async (detachPayload) => {
    const { signJws, publicJwk } = await createEs256Context()

    await expect(
      signCompactJws({
        protectedHeader: unencodedHeader,
        payload: binaryPayload,
        signer: { method: 'jwk', alg: 'ES256', publicJwk },
        signJwsCallback: signJws,
        detachPayload,
      })
    ).rejects.toThrow(notSupported)
  })
})

describe('signing and verifying an unencoded payload', () => {
  it('verifies a compact JWS that carries its unencoded payload', async () => {
    const { signJws, verifyJws, publicJwk } = await createEs256Context()

    const { compact } = await signCompactJws({
      protectedHeader: unencodedHeader,
      payload: '$transfer:1000',
      signer: { method: 'jwk', alg: 'ES256', publicJwk },
      signJwsCallback: signJws,
    })
    expect(compact.split('.')[1]).toBe('$transfer:1000')

    const jws = parseJws({ jws: compact, understoodCriticalParameters: ['b64'] })
    const { signer } = await verifyJwsSignature({ jws, verifyJwsCallback: verifyJws })

    expect(signer.publicJwk).toEqual(publicJwk)
  })

  it('verifies a detached unencoded payload that contains a period', async () => {
    const { signJws, verifyJws, publicJwk } = await createEs256Context()

    const { compact } = await signCompactJws({
      protectedHeader: unencodedHeader,
      payload: 'transfer 10.50',
      signer: { method: 'jwk', alg: 'ES256', publicJwk },
      signJwsCallback: signJws,
      detachPayload: true,
    })

    const jws = parseJws({ jws: compact, detachedPayload: 'transfer 10.50', understoodCriticalParameters: ['b64'] })
    const { signer } = await verifyJwsSignature({ jws, verifyJwsCallback: verifyJws })

    expect(signer.publicJwk).toEqual(publicJwk)
  })

  it('refuses to carry an unencoded payload that contains a period in a compact JWS', async () => {
    const { signJws, publicJwk } = await createEs256Context()

    await expect(
      signCompactJws({
        protectedHeader: unencodedHeader,
        payload: 'transfer 10.50',
        signer: { method: 'jwk', alg: 'ES256', publicJwk },
        signJwsCallback: signJws,
      })
    ).rejects.toThrow(
      joseError(JoseInvalidArgumentError, `The payload is unencoded ('b64' is false) and contains a '.'`)
    )
  })
})

/**
 * RFC 7797 section 5.2: the payload of a compact JWS that carries it unencoded is "the ASCII
 * representation of the characters in the payload string", and only the space and the printable ASCII
 * characters other than '.' (%x20-2D and %x2F-7E) may be included. A detached payload (section 5.1)
 * and the payload of a JSON serialization, which is a JSON string, are not limited this way.
 */
describe('the characters of an unencoded payload in a compact JWS', () => {
  const outsidePrintableAscii = `The payload is unencoded ('b64' is false) and contains a character outside printable ASCII`
  const containsPeriod = `The payload is unencoded ('b64' is false) and contains a '.'`

  /** Every character RFC 7797 lets a compact JWS carry in an unencoded payload: %x20-2D and %x2F-7E. */
  const everyAllowedCharacter = Array.from({ length: 0x7e - 0x20 + 1 }, (_, index) => String.fromCharCode(0x20 + index))
    .filter((character) => character !== '.')
    .join('')

  const sign = async (payload: string, detachPayload = false) => {
    const { signJws, publicJwk } = await createEs256Context()
    return signCompactJws({
      protectedHeader: unencodedHeader,
      payload,
      signer: { method: 'jwk', alg: 'ES256', publicJwk },
      signJwsCallback: signJws,
      detachPayload,
    })
  }

  it.each([
    ['a non-ASCII letter', 'h\u00e9llo'],
    ['an emoji', 'paid \u{1F4B8}'],
    ['a line break', 'line\nbreak'],
    ['a tab', 'tab\there'],
    ['the DEL control character', 'del\u007f'],
  ])('refuses to carry an unencoded payload with %s', async (_, payload) => {
    await expect(sign(payload)).rejects.toThrow(joseError(JoseInvalidArgumentError, outsidePrintableAscii))
  })

  it('reports a period rather than a character outside printable ASCII when the payload has both', async () => {
    await expect(sign('caf\u00e9 3.50')).rejects.toThrow(joseError(JoseInvalidArgumentError, containsPeriod))
  })

  it('refuses before the signing callback is called', async () => {
    const { publicJwk } = await createEs256Context()
    let callbackCalled = false

    await expect(
      signCompactJws({
        protectedHeader: unencodedHeader,
        payload: 'h\u00e9llo',
        signer: { method: 'jwk', alg: 'ES256', publicJwk },
        signJwsCallback: () => {
          callbackCalled = true
          return { signature: 'c2lnbmF0dXJl', signerJwk: publicJwk }
        },
      })
    ).rejects.toThrow(JoseInvalidArgumentError)
    expect(callbackCalled).toBe(false)
  })

  it('carries every printable ASCII character other than the period', async () => {
    const { compact } = await sign(everyAllowedCharacter)

    expect(compact.split('.')[1]).toBe(everyAllowedCharacter)
  })

  it('parses a compact JWS that carries every printable ASCII character other than the period', async () => {
    const { compact } = await sign(everyAllowedCharacter)

    expect(parseJws({ jws: compact, understoodCriticalParameters: ['b64'] }).payload).toEqual(
      stringToBytes(everyAllowedCharacter)
    )
  })

  it('signs a detached unencoded payload with characters outside printable ASCII', async () => {
    const { compact, signingInput } = await sign('caf\u00e9\n3.50', true)

    expect(compact.split('.')[1]).toBe('')
    expect(signingInput.split('.').slice(1).join('.')).toBe('caf\u00e9\n3.50')
  })

  it('rejects parsing a compact JWS whose unencoded payload has a character outside printable ASCII', () => {
    const jws = `${encode(unencodedHeader)}.h\u00e9llo.c2ln`

    expect(() => parseJws({ jws, understoodCriticalParameters: ['b64'] })).toThrow(
      joseError(JoseParseError, outsidePrintableAscii)
    )
  })

  it('rejects parsing a compact JWS whose unencoded payload has a line break', () => {
    const jws = `${encode(unencodedHeader)}.line\nbreak.c2ln`

    expect(() => parseJws({ jws, understoodCriticalParameters: ['b64'] })).toThrow(
      joseError(JoseParseError, outsidePrintableAscii)
    )
  })

  it('rejects parsing a compact JWS whose unencoded payload contains a period as such', () => {
    const jws = `${encode(unencodedHeader)}.transfer 10.50.c2ln`

    expect(() => parseJws({ jws, understoodCriticalParameters: ['b64'] })).toThrow(
      joseError(JoseParseError, containsPeriod)
    )
  })

  it('rejects a compact JWS of more than three parts whose header does not unencode the payload as such', () => {
    expect(() => parseJws({ jws: `${encode({ alg: 'ES256' })}.cGF5.bG9hZA.c2ln` })).toThrow(
      joseError(JoseParseError, 'a compact JWS must consist of exactly three parts')
    )
  })

  it('verifies a flattened JWS whose unencoded payload has characters outside printable ASCII', async () => {
    const { signJws, verifyJws, publicJwk } = await createEs256Context()
    const payload = 'caf\u00e9\n3.50'
    const { compact } = await signCompactJws({
      protectedHeader: unencodedHeader,
      payload,
      signer: { method: 'jwk', alg: 'ES256', publicJwk },
      signJwsCallback: signJws,
      detachPayload: true,
    })
    const [header, , signature] = compact.split('.')

    const jws = parseJws({ jws: { protected: header, payload, signature }, understoodCriticalParameters: ['b64'] })
    const { signer } = await verifyJwsSignature({ jws, verifyJwsCallback: verifyJws })

    expect(signer.publicJwk).toEqual(publicJwk)
  })
})
