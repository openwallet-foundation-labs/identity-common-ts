import type { Jwk } from '@owf/jose'
import * as jose from 'jose'
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest'
import { callbacks, getSignJwsCallback } from '../../../../oauth2/src/__tests__/util.mjs'
import { createOpenid4vpAuthorizationResponse } from '../../authorization-response/create-authorization-response.js'

const now = new Date('2026-01-01T00:00:00.000Z')
const seconds = (date: Date) => Math.floor(date.getTime() / 1000)

// JARM Section 2.1: `exp` is the expiration of the response, RECOMMENDED to be at most 10 minutes
describe('createOpenid4vpAuthorizationResponse with a signed JARM response', () => {
  beforeEach(() => {
    vi.useFakeTimers({ toFake: ['Date'] })
    vi.setSystemTime(now)
  })
  afterEach(() => {
    vi.useRealTimers()
  })

  const createResponse = async (expiresInSeconds?: number) => {
    const { privateKey, publicKey } = await jose.generateKeyPair('ES256', { extractable: true })
    const publicJwk = (await jose.exportJWK(publicKey)) as Jwk

    const { authorizationResponsePayload } = await createOpenid4vpAuthorizationResponse({
      authorizationRequestPayload: {
        client_id: 'verifier',
        response_type: 'vp_token',
        response_mode: 'direct_post.jwt',
        response_uri: 'https://verifier.example/response',
        nonce: 'nonce',
        client_metadata: { jwks: { keys: [{ ...publicJwk, use: 'enc' }] } },
      },
      authorizationResponsePayload: { vp_token: { pid: ['vp'] } },
      jarm: {
        jwtSigner: { method: 'jwk', alg: 'ES256', publicJwk },
        authorizationServer: 'https://wallet.example',
        audience: 'verifier',
        serverMetadata: {
          authorization_signing_alg_values_supported: ['ES256'],
          authorization_encryption_alg_values_supported: ['ECDH-ES'],
          authorization_encryption_enc_values_supported: ['A128GCM'],
        },
        expiresInSeconds,
      },
      callbacks: { ...callbacks, signJws: getSignJwsCallback([(await jose.exportJWK(privateKey)) as Jwk]) } as never,
    })

    return authorizationResponsePayload as typeof authorizationResponsePayload & { exp: number }
  }

  test('expires the response expiresInSeconds after now', async () => {
    expect((await createResponse(60)).exp).toBe(seconds(now) + 60)
  })

  test('expires the response 10 minutes after now by default', async () => {
    expect((await createResponse()).exp).toBe(seconds(now) + 600)
  })
})
