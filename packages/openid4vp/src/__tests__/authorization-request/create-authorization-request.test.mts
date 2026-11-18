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

  const unsignedCallbacks = { ...callbacks, signJws: getSignJwsCallback([]) }
  const dcqlQuery = { credentials: [{ id: 'pid', format: 'dc+sd-jwt', meta: { vct_values: ['pid'] } }] }

  test('returns an unsigned DC API request as a JSON object (OpenID4VP 1.0 Appendix A.3)', async () => {
    const authorizationRequestPayload = {
      response_type: 'vp_token',
      response_mode: 'dc_api',
      nonce: 'nonce',
      dcql_query: dcqlQuery,
    } as const

    const { authorizationRequest } = await createOpenid4vpAuthorizationRequest({
      authorizationRequestPayload,
      callbacks: unsignedCallbacks,
    })

    expect(authorizationRequest).toEqual(authorizationRequestPayload)
  })

  test('returns a signed DC API request as a JSON object with the request object (OpenID4VP 1.0 Appendix A.3)', async () => {
    const { privateKey, publicKey } = await jose.generateKeyPair('ES256', { extractable: true })
    const publicJwk = (await jose.exportJWK(publicKey)) as Jwk

    const { authorizationRequest, jar } = await createOpenid4vpAuthorizationRequest({
      authorizationRequestPayload: {
        client_id: 'x509_san_dns:verifier.example',
        response_type: 'vp_token',
        response_mode: 'dc_api',
        expected_origins: ['https://verifier.example'],
        nonce: 'nonce',
        dcql_query: dcqlQuery,
      },
      jar: { jwtSigner: { method: 'jwk', alg: 'ES256', publicJwk }, expiresInSeconds: 300 },
      callbacks: { ...callbacks, signJws: getSignJwsCallback([(await jose.exportJWK(privateKey)) as Jwk]) },
    })

    expect(authorizationRequest).toEqual({
      client_id: 'x509_san_dns:verifier.example',
      request: jar?.authorizationRequestJwt,
    })
  })

  test('returns an unsigned request with a redirect_uri client id as a uri', async () => {
    const { authorizationRequest } = await createOpenid4vpAuthorizationRequest({
      authorizationRequestPayload: {
        client_id: 'redirect_uri:https://verifier.example/response',
        response_type: 'vp_token',
        response_mode: 'direct_post',
        response_uri: 'https://verifier.example/response',
        nonce: 'nonce',
        dcql_query: dcqlQuery,
      },
      callbacks: unsignedCallbacks,
    })

    expect(authorizationRequest).toEqual(expect.stringMatching(/^openid4vp:\/\/\?/))
  })

  test('rejects an unsigned request with a client id prefix that requires signing (OpenID4VP 1.0 Section 5.9.3)', async () => {
    await expect(
      createOpenid4vpAuthorizationRequest({
        authorizationRequestPayload: {
          client_id: 'x509_san_dns:verifier.example',
          response_type: 'vp_token',
          response_mode: 'direct_post',
          response_uri: 'https://verifier.example/response',
          nonce: 'nonce',
          dcql_query: dcqlQuery,
        },
        callbacks: unsignedCallbacks,
      })
    ).rejects.toThrow("Using client identifier prefix 'x509_san_dns' requires a signed JAR request.")
  })
})
