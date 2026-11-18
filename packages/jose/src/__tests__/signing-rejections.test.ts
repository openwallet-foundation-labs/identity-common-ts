import { describe, expect, it } from 'vitest'
import z from 'zod'
import type { SignJwsCallback } from '../callbacks'
import { JoseInvalidArgumentError, JoseNotSupportedError, JoseValidationError } from '../error'
import { signCompactJws } from '../jws/sign-jws'
import { decodeJwt } from '../jwt/decode-jwt'
import { signJwt } from '../jwt/sign-jwt'
import { zJwtPayload } from '../jwt/z-jwt'
import { createEs256Context } from './context'

/** These tests are about what is refused, so the signature itself never matters. */
const signingWith =
  (signature: unknown): SignJwsCallback =>
  () => ({ signature: signature as string, signerJwk: { kty: 'EC', crv: 'P-256', x: 'x', y: 'y' } })

describe('signCompactJws', () => {
  it('refuses a signer whose alg differs from the alg of the header', async () => {
    let calls = 0

    await expect(
      signCompactJws({
        protectedHeader: { alg: 'ES384' },
        payload: { iss: 'https://issuer.example' },
        signer: { method: 'custom', alg: 'ES256' },
        signJwsCallback: () => {
          calls++
          return { signature: 'c2ln', signerJwk: { kty: 'EC' } }
        },
      })
    ).rejects.toThrow(
      new JoseInvalidArgumentError(
        `Unable to sign the JWS, the header says alg 'ES384' but the signer signs with alg 'ES256'.`
      )
    )
    expect(calls).toBe(0)
  })

  it.each([
    ['standard base64', 'ab+/cd'],
    ['padded base64url', 'YWJjZA=='],
    ['empty', ''],
    ['not a string', new Uint8Array([1, 2, 3])],
  ])('refuses a callback signature that is %s', async (_description, signature) => {
    await expect(
      signCompactJws({
        protectedHeader: { alg: 'ES256' },
        payload: { iss: 'https://issuer.example' },
        signer: { method: 'custom', alg: 'ES256' },
        signJwsCallback: signingWith(signature),
      })
    ).rejects.toThrow(
      new JoseInvalidArgumentError(
        'Unable to sign the JWS, the signature returned by the signing callback is not a non-empty base64url string.'
      )
    )
  })

  it('returns the compact JWS with the signature the callback returned', async () => {
    const { compact, signature } = await signCompactJws({
      protectedHeader: { alg: 'ES256' },
      payload: { iss: 'https://issuer.example' },
      signer: { method: 'custom', alg: 'ES256' },
      signJwsCallback: signingWith('c2ln-_'),
    })

    expect(signature).toBe('c2ln-_')
    expect(compact.split('.')[2]).toBe('c2ln-_')
  })
})

/** What `signJwt` produces is what `decodeJwt` accepts. */
describe('signJwt', () => {
  it('refuses a payload schema that turns a registered claim into something that is not a NumericDate', async () => {
    const { signJws, publicJwk } = await createEs256Context()
    const zPayload = z
      .object({ ...zJwtPayload.shape, exp: z.number().transform((exp) => new Date(exp * 1000)) })
      .loose()

    await expect(
      signJwt({
        payload: { iss: 'https://issuer.example', exp: 1_800_000_000 },
        payloadSchema: zPayload,
        signer: { method: 'jwk', alg: 'ES256', publicJwk },
        signJwsCallback: signJws,
      })
    ).rejects.toThrow(JoseValidationError)
  })

  it('refuses a payload schema that fills in a registered claim of the wrong type', async () => {
    const { signJws, publicJwk } = await createEs256Context()
    const zPayload = z.object({ ...zJwtPayload.shape, aud: z.any().default(42) }).loose()

    await expect(
      signJwt({
        payload: { iss: 'https://issuer.example' },
        payloadSchema: zPayload,
        signer: { method: 'jwk', alg: 'ES256', publicJwk },
        signJwsCallback: signJws,
      })
    ).rejects.toThrow('Unable to sign the JWT, invalid claims set')
  })

  it('refuses a header with an unencoded payload', async () => {
    const { signJws, publicJwk } = await createEs256Context()

    await expect(
      signJwt({
        header: { b64: false, crit: ['b64'] },
        payload: { iss: 'https://issuer.example' },
        signer: { method: 'jwk', alg: 'ES256', publicJwk },
        signJwsCallback: signJws,
      })
    ).rejects.toThrow(
      new JoseNotSupportedError(
        `Unable to sign the JWT, its header sets 'b64' to false. An unencoded payload is not valid for a JWT.`
      )
    )
  })

  it('signs a claim a payload schema fills in, as a token decodeJwt accepts', async () => {
    const { signJws, publicJwk } = await createEs256Context()
    const zPayload = z.object({ ...zJwtPayload.shape, iss: z.string().default('https://issuer.example') }).loose()

    const { jwt } = await signJwt({
      payload: {},
      payloadSchema: zPayload,
      signer: { method: 'jwk', alg: 'ES256', publicJwk },
      signJwsCallback: signJws,
    })

    expect(decodeJwt({ jwt }).payload).toEqual({ iss: 'https://issuer.example' })
  })
})
