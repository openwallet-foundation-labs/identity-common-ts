import { base64urlEncode } from '@owf/identity-common'
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
        callbacks: { ...callbacks, verifyJws: () => Promise.reject(), decryptJwe: () => Promise.reject() },
      })
    ).rejects.toThrow('Invalid authorization request')
  })

  test('does not parse an unsigned request with an http response_uri as JAR', () => {
    expect(() => parseOpenid4vpAuthorizationRequest({ authorizationRequest: insecureRequest })).toThrow()
  })

  describe('with the result of parseOpenid4vpAuthorizationRequest', () => {
    const request = {
      ...insecureRequest,
      client_id: 'redirect_uri:https://bank.example/cb',
      response_uri: 'https://bank.example/cb',
    }
    const options = {
      responseMode: { type: 'direct_post' },
      callbacks: { ...callbacks, verifyJws: () => Promise.reject(), decryptJwe: () => Promise.reject() },
    } as const

    test('resolves to the same as with the params', async () => {
      const parsed = parseOpenid4vpAuthorizationRequest({ authorizationRequest: request })

      const resolved = await resolveOpenid4vpAuthorizationRequest({ ...options, parsedAuthorizationRequest: parsed })
      expect(resolved).toEqual(
        await resolveOpenid4vpAuthorizationRequest({ ...options, authorizationRequestPayload: parsed.params })
      )
      // Not parsed a second time
      expect(resolved.authorizationRequestPayload).toBe(parsed.params)
    })

    test('resolves a JAR request to the same as with the params', async () => {
      const encode = (value: object) => base64urlEncode(JSON.stringify(value))
      const client_id = 'x509_san_dns:example.com'
      const requestObject = `${encode({ alg: 'ES256', typ: 'oauth-authz-req+jwt', x5c: ['MAA='] })}.${encode({
        ...request,
        client_id,
      })}.c2lnbmF0dXJl`

      const parsed = parseOpenid4vpAuthorizationRequest({ authorizationRequest: { client_id, request: requestObject } })
      expect(parsed.type).toBe('jar')

      const jarOptions = {
        ...options,
        callbacks: { ...callbacks, verifyJws: () => ({ verified: false as const }) },
      }
      const error = await resolveOpenid4vpAuthorizationRequest({
        ...jarOptions,
        parsedAuthorizationRequest: parsed,
      }).catch((error) => error)

      // The request object is decoded and its signature checked
      expect(error).toMatchObject({
        errorResponse: { error: 'invalid_request_object' },
        authorizationRequestPayload: { client_id, nonce: 'nonce' },
      })
      expect(error).toEqual(
        await resolveOpenid4vpAuthorizationRequest({
          ...jarOptions,
          authorizationRequestPayload: parsed.params,
        }).catch((error) => error)
      )
    })

    test.each(['dcql_query', 'presentation_definition'])(
      'decodes a %s JSON string, and rejects one that is not an object',
      (param) => {
        const parse = (value: string) =>
          parseOpenid4vpAuthorizationRequest({ authorizationRequest: { ...request, [param]: value } })

        expect(parse('{"a":1}').params[param]).toEqual({ a: 1 })
        expect(() => parse('[1]')).toThrow()
        expect(() => parse('"{\\"a\\":1}"')).toThrow()
      }
    )
  })
})
