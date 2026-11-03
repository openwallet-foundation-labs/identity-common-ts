import { decodeJwt, type Jwk } from '@owf/jose'
import * as jose from 'jose'
import { describe, expect, test } from 'vitest'
import { callbacks, getSignJwsCallback } from '../../../../oauth2/src/__tests__/util.mjs'
import { createOpenid4vpAuthorizationRequest } from '../../authorization-request/create-authorization-request.js'

const now = new Date('2026-01-01T00:00:00.000Z')
const seconds = (date: Date) => Math.floor(date.getTime() / 1000)

describe('createOpenid4vpAuthorizationRequest', () => {
  test('uses now for the iat and exp of the signed request object', async () => {
    const { privateKey, publicKey } = await jose.generateKeyPair('ES256', { extractable: true })
    const publicJwk = (await jose.exportJWK(publicKey)) as Jwk

    const { jar } = await createOpenid4vpAuthorizationRequest({
      authorizationRequestPayload: {
        client_id: 'verifier',
        response_type: 'vp_token',
        response_mode: 'direct_post',
        response_uri: 'https://verifier.example/response',
        nonce: 'nonce',
        dcql_query: { credentials: [{ id: 'pid', format: 'dc+sd-jwt', meta: { vct_values: ['pid'] } }] },
      },
      jar: { jwtSigner: { method: 'jwk', alg: 'ES256', publicJwk }, expiresInSeconds: 300 },
      callbacks: { ...callbacks, signJws: getSignJwsCallback([(await jose.exportJWK(privateKey)) as Jwk]) },
      now,
    })

    expect(decodeJwt({ jwt: jar?.authorizationRequestJwt as string }).payload).toMatchObject({
      iat: seconds(now),
      exp: seconds(now) + 300,
    })
  })
})
