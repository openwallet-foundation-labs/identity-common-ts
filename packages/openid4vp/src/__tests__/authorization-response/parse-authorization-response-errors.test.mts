import { Oauth2ServerErrorResponseError } from '@openid4vc/oauth2'
import { JsonParseError } from '@openid4vc/utils'
import { base64url, stringToBytes, ValidationError } from '@owf/identity-common'
import { JoseParseError, type Jwk, signJwt } from '@owf/jose'
import * as jose from 'jose'
import { describe, expect, test } from 'vitest'
import { callbacks, getSignJwsCallback } from '../../../../oauth2/src/__tests__/util.mjs'
import { Openid4vpAuthorizationResponseError } from '../../authorization-response/Openid4vpAuthorizationResponseError.js'
import { parseOpenid4vpAuthorizationResponse } from '../../authorization-response/parse-authorization-response.js'
import { validateOpenid4vpAuthorizationResponsePayload } from '../../authorization-response/validate-authorization-response.js'

const dcqlQuery = { credentials: [{ id: 'pid', format: 'dc+sd-jwt', meta: { vct_values: ['pid'] } }] }
const clientId = 'redirect_uri:https://verifier.example/response'

const authorizationRequestPayload = (responseMode: 'direct_post' | 'direct_post.jwt') =>
  ({
    client_id: clientId,
    response_type: 'vp_token',
    response_mode: responseMode,
    response_uri: 'https://verifier.example/response',
    nonce: 'nonce',
    dcql_query: dcqlQuery,
  }) as const

const encodeHeader = (header: unknown) => base64url.encode(stringToBytes(JSON.stringify(header)))

// Only the header is read before the decryptJwe callback, which returns the payload of the test
const jwe = `${encodeHeader({ alg: 'ECDH-ES', enc: 'A128GCM' })}..aXY.Y3Q.dGFn`

const parse = (authorizationResponse: Record<string, unknown>, decryptedPayload?: string) =>
  parseOpenid4vpAuthorizationResponse({
    authorizationResponse,
    authorizationRequestPayload: authorizationRequestPayload(
      authorizationResponse.response ? 'direct_post.jwt' : 'direct_post'
    ),
    callbacks: {
      ...callbacks,
      decryptJwe: () => ({ decrypted: true, decryptionJwk: { kty: 'EC' }, payload: decryptedPayload ?? '' }),
    },
  })

const createSignedResponse = async (payload: Record<string, unknown>) => {
  const { privateKey, publicKey } = await jose.generateKeyPair('ES256', { extractable: true })
  const publicJwk = (await jose.exportJWK(publicKey)) as Jwk
  const { jwt } = await signJwt({
    header: { jwk: publicJwk },
    payload: { iss: 'https://wallet.example', aud: clientId, exp: Math.floor(Date.now() / 1000) + 60, ...payload },
    signer: { method: 'jwk', alg: 'ES256', publicJwk },
    signJwsCallback: getSignJwsCallback([(await jose.exportJWK(privateKey)) as Jwk]),
  })
  return jwt
}

const invalidRequest = async (promise: Promise<unknown>) => {
  const error = await promise.then(
    () => undefined,
    (error: Oauth2ServerErrorResponseError) => error
  )
  expect(error).toBeInstanceOf(Oauth2ServerErrorResponseError)
  expect(error?.errorResponse.error).toBe('invalid_request')
  expect(error?.status).toBe(400)
  return error as Oauth2ServerErrorResponseError
}

describe('parseOpenid4vpAuthorizationResponse with a response that is not valid', () => {
  test('throws invalid_request for a response parameter that is not a JWT or JWE', async () => {
    const error = await invalidRequest(parse({ response: 'not-a-jwt' }))
    expect(error.errorResponse.error_description).toBe('Invalid jarm authorization response jwt.')
    expect(error.cause).toBeInstanceOf(ValidationError)
  })

  test('throws invalid_request for a response parameter that is not a string', async () => {
    const error = await invalidRequest(parse({ response: 123 }))
    expect(error.errorResponse.error_description).toBe('Invalid jarm authorization response jwt.')
    expect(error.cause).toBeInstanceOf(ValidationError)
  })

  test('throws invalid_request for a JWE whose header is not JSON', async () => {
    const error = await invalidRequest(
      parse({ response: `${base64url.encode(stringToBytes('header'))}..aXY.Y3Q.dGFn` })
    )
    expect(error.errorResponse.error_description).toBe('Invalid JARM authorization response.')
    expect(error.cause).toBeInstanceOf(JoseParseError)
  })

  // OpenID4VP 1.0 Section 8.3.1: the encrypted response contains the parameters as a JSON object
  test('throws invalid_request for decrypted content that is not JSON, without the content', async () => {
    const error = await invalidRequest(parse({ response: jwe }, 'secret-plaintext'))
    expect(error.errorResponse.error_description).toBe('Invalid JARM authorization response.')
    expect(JSON.stringify(error.errorResponse)).not.toContain('secret-plaintext')
    expect(error.message).not.toContain('secret-plaintext')
    // The cause is not sent, and keeps the content for debugging
    expect(error.cause).toBeInstanceOf(JsonParseError)
  })

  test('throws invalid_request for decrypted content that is not a JSON object', async () => {
    const error = await invalidRequest(parse({ response: jwe }, '[1,2,3]'))
    expect(error.errorResponse.error_description).toBe('Invalid JARM authorization response')
    expect(error.cause).toBeInstanceOf(ValidationError)
  })

  test('throws invalid_request for a decrypted response without vp_token', async () => {
    const error = await invalidRequest(parse({ response: jwe }, JSON.stringify({ state: 'state' })))
    expect(error.errorResponse.error_description).toBe('Failed to parse openid4vp authorization response.')
    expect(error.cause).toBeInstanceOf(ValidationError)
  })

  test('throws invalid_request for a signed response whose vp_token is not an object when the request has a dcql_query', async () => {
    const error = await invalidRequest(parse({ response: await createSignedResponse({ vp_token: 'presentation' }) }))
    expect(error.errorResponse.error_description).toBe(
      'Could not parse dcql vp_token. Expected an object where the values are encoded presentations'
    )
    expect(error.cause).toBeInstanceOf(ValidationError)
  })

  test('throws invalid_request for a response without vp_token, and keeps the issues in the message', async () => {
    const error = await invalidRequest(parse({ state: 'state' }))
    expect(error.errorResponse.error_description).toBe('Failed to parse openid4vp authorization response.')
    // A verifier that logs or stores the message still sees which parameter is not valid
    expect(error.message).toContain('vp_token')
    expect(error.cause).toBeInstanceOf(ValidationError)
  })

  test('throws invalid_request for a vp_token that is not an object when the request has a dcql_query', async () => {
    const error = await invalidRequest(parse({ vp_token: 'presentation' }))
    expect(error.errorResponse.error_description).toBe(
      'Could not parse dcql vp_token. Expected an object where the values are encoded presentations'
    )
    expect(error.cause).toBeInstanceOf(ValidationError)
  })

  // RFC 6749 Section 5.2: the error_description only contains printable ASCII except '"' and '\'
  test('does not put the keys of the response in the error description', async () => {
    const error = await invalidRequest(parse({ vp_token: { 'pid"\n<script>': [5] } }))
    expect(error.errorResponse.error_description).toBe(
      'Could not parse dcql vp_token. Expected an object where the values are encoded presentations'
    )
    expect(error.errorResponse.error_description).toMatch(/^[\x20-\x21\x23-\x5B\x5D-\x7E]+$/)
    expect(error.errorResponse.error_description).not.toContain('<script>')
  })
})

describe('validateOpenid4vpAuthorizationResponsePayload with a response that is not valid', () => {
  test('throws invalid_request for a vp_token that is not an object when the request has a dcql_query', async () => {
    const error = await invalidRequest(
      Promise.resolve().then(() =>
        validateOpenid4vpAuthorizationResponsePayload({
          authorizationRequestPayload: authorizationRequestPayload('direct_post'),
          authorizationResponsePayload: { vp_token: 'presentation' },
        })
      )
    )
    expect(error.errorResponse.error_description).toBe(
      'Could not parse dcql vp_token. Expected an object where the values are encoded presentations'
    )
    expect(error.cause).toBeInstanceOf(ValidationError)
  })

  test('throws invalid_request for a state that does not match, without the state values in the message', async () => {
    const error = await invalidRequest(
      Promise.resolve().then(() =>
        validateOpenid4vpAuthorizationResponsePayload({
          authorizationRequestPayload: { ...authorizationRequestPayload('direct_post'), state: 'expected-state' },
          authorizationResponsePayload: { state: 'received-state', vp_token: {} },
        })
      )
    )
    expect(error.message).not.toContain('expected-state')
    expect(error.message).not.toContain('received-state')
    expect(error.sensitive).toEqual({ expectedState: 'expected-state', receivedState: 'received-state' })
  })
})

// OpenID4VP 1.0 Section 8.5: the wallet can return an authorization error response instead
describe('parseOpenid4vpAuthorizationResponse with an authorization error response', () => {
  test('throws the Openid4vpAuthorizationResponseError as is', async () => {
    await expect(parse({ error: 'access_denied' })).rejects.toBeInstanceOf(Openid4vpAuthorizationResponseError)
  })

  test('throws the Openid4vpAuthorizationResponseError as is when the response is encrypted', async () => {
    await expect(parse({ response: jwe }, JSON.stringify({ error: 'access_denied' }))).rejects.toBeInstanceOf(
      Openid4vpAuthorizationResponseError
    )
  })
})

describe('parseOpenid4vpAuthorizationResponse with a callback that throws', () => {
  test('throws an error of the callback that is not an IdentityError as is', async () => {
    const callbackError = new Error('Key not found')
    const error = await parseOpenid4vpAuthorizationResponse({
      authorizationResponse: { response: jwe },
      authorizationRequestPayload: authorizationRequestPayload('direct_post.jwt'),
      callbacks: {
        ...callbacks,
        decryptJwe: () => {
          throw callbackError
        },
      },
    }).catch((error) => error)

    expect(error).toBe(callbackError)
  })
})
