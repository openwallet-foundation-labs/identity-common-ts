import { type Jwk, signJwt } from '@owf/jose'
import * as jose from 'jose'
import { describe, expect, test } from 'vitest'
import { callbacks, getSignJwsCallback } from '../../../../oauth2/src/__tests__/util.mjs'
import { Openid4vpVerifier } from '../../Openid4vpVerifier.js'

const now = new Date('2026-01-01T00:00:00.000Z')
const seconds = (date: Date) => Math.floor(date.getTime() / 1000)

const authorizationRequestPayload = {
  client_id: 'verifier',
  response_type: 'vp_token',
  response_mode: 'direct_post.jwt',
  response_uri: 'https://verifier.example/response',
  nonce: 'nonce',
  dcql_query: { credentials: [{ id: 'pid', format: 'dc+sd-jwt', meta: { vct_values: ['pid'] } }] },
} as const

describe('Openid4vpVerifier', () => {
  test('applies its allowed skew to a JARM response, and a per-call one takes precedence', async () => {
    const { privateKey, publicKey } = await jose.generateKeyPair('ES256', { extractable: true })
    const publicJwk = (await jose.exportJWK(publicKey)) as Jwk
    const { jwt: response } = await signJwt({
      header: { jwk: publicJwk },
      // Expired 10 seconds ago
      payload: { iss: 'https://wallet.example', aud: 'verifier', exp: seconds(now) - 10, vp_token: { pid: ['vp'] } },
      signer: { method: 'jwk', alg: 'ES256', publicJwk },
      signJwsCallback: getSignJwsCallback([(await jose.exportJWK(privateKey)) as Jwk]),
    })

    const parse = (allowedSkewInSeconds?: number) =>
      new Openid4vpVerifier({
        callbacks: { ...callbacks, signJws: getSignJwsCallback([]) },
        allowedSkewInSeconds: 0,
      }).parseOpenid4vpAuthorizationResponse({
        authorizationResponse: { response },
        authorizationRequestPayload,
        callbacks,
        now,
        allowedSkewInSeconds,
      })

    await expect(parse()).rejects.toThrow('The JARM authorization response is expired.')
    await expect(parse(30)).resolves.toMatchObject({ jarm: { issuer: 'https://wallet.example' } })
  })
})
