import { describe, expect, test } from 'vitest'
import { callbacks } from '../../../../oauth2/src/__tests__/util.mjs'
import { parseOpenid4vpAuthorizationRequest } from '../../authorization-request/parse-authorization-request-params.js'
import { resolveOpenid4vpAuthorizationRequest } from '../../authorization-request/resolve-authorization-request.js'

describe('Resolve Authorization Request', () => {
  // Fails the openid4vp schema, and must not fall through to the JAR schema
  const insecureRequest = {
    response_type: 'vp_token',
    response_mode: 'direct_post',
    client_id: 'redirect_uri:http://bank.example/cb',
    response_uri: 'http://bank.example/cb',
    nonce: 'nonce',
    dcql_query: { credentials: [{ id: 'pid', format: 'dc+sd-jwt', meta: { vct_values: ['pid'] } }] },
  }

  test('rejects an unsigned request with an http response_uri', async () => {
    await expect(
      resolveOpenid4vpAuthorizationRequest({
        authorizationRequestPayload: insecureRequest,
        responseMode: { type: 'direct_post' },
        callbacks: { ...callbacks, verifyJwt: () => Promise.reject(), decryptJwe: () => Promise.reject() },
      })
    ).rejects.toThrow('Invalid authorization request')
  })

  test('does not parse an unsigned request with an http response_uri as JAR', () => {
    expect(() => parseOpenid4vpAuthorizationRequest({ authorizationRequest: insecureRequest })).toThrow()
  })
})
