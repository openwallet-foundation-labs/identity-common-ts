import { encodeToBase64Url } from '@openid4vc/utils'
import { HttpResponse, http } from 'msw'
import { setupServer } from 'msw/node'
import { afterAll, afterEach, beforeAll, describe, expect, test } from 'vitest'
import { getSignJwtCallback, callbacks as partialCallbacks } from '../../../oauth2/src/__tests__/util.mjs'
import { parseOpenid4VpAuthorizationResponsePayload } from '../authorization-response/parse-authorization-response-payload.js'
import {
  createOpenid4vpAuthorizationResponse,
  isOpenid4vpAuthorizationRequestDcApi,
  isOpenid4vpAuthorizationRequestIae,
  Openid4vpAuthorizationRequestError,
  Openid4vpAuthorizationResponseError,
  resolveOpenid4vpAuthorizationRequest,
  submitOpenid4vpAuthorizationResponse,
} from '../index.js'

const server = setupServer()

const callbacks = {
  ...partialCallbacks,
  // msw replaces the global fetch when the server starts listening
  fetch: (...args: Parameters<typeof fetch>) => fetch(...args),
  signJwt: getSignJwtCallback([]),
  encryptJwe: () => {
    throw new Error('Not implemented')
  },
  decryptJwe: () => {
    throw new Error('Not implemented')
  },
}

const responseUri = 'https://example.com/response_uri'
const dcqlQuery = { credentials: [{ id: 'pid', format: 'dc+sd-jwt', meta: { vct_values: ['pid'] } }] }

// With the `redirect_uri` prefix the client identifier is the response uri, so the client is
// authenticated once the request is valid in that respect.
const authenticatedRequest = {
  response_type: 'vp_token',
  response_mode: 'direct_post',
  client_id: `redirect_uri:${responseUri}`,
  response_uri: responseUri,
  nonce: 'nonce',
  state: 'state',
  dcql_query: dcqlQuery,
} as const

const encJwk = {
  kty: 'EC',
  alg: 'ECDH-ES',
  crv: 'P-256',
  x: 'PHVtfGzwfShN50aP1Vqw9PW2y1Hwe_lvprL2Ev-Kzbg',
  y: 'qCj6yA31O3Sr6FCOGb1SO5XdpfVySG1uk5cMr6zmq9c',
  use: 'enc',
} as const

describe('resolveOpenid4vpAuthorizationRequest errors', () => {
  test('throws an Openid4vpAuthorizationRequestError for invalid transaction data from an authenticated client', async () => {
    const error = await resolveOpenid4vpAuthorizationRequest({
      authorizationRequestPayload: {
        ...authenticatedRequest,
        transaction_data: [encodeToBase64Url(JSON.stringify({ type: 'payment' }))],
      },
      callbacks,
      responseMode: { type: 'direct_post' },
    }).catch((error) => error)

    expect(error).toBeInstanceOf(Openid4vpAuthorizationRequestError)
    expect(error).toMatchObject({
      isClientAuthenticated: true,
      errorResponse: { error: 'invalid_transaction_data' },
      authorizationRequestPayload: { response_uri: responseUri, state: 'state' },
      client: { prefix: 'redirect_uri', identifier: responseUri },
      jar: undefined,
    })
  })

  test('throws an Openid4vpAuthorizationRequestError for an invalid request from an authenticated client', async () => {
    const error = await resolveOpenid4vpAuthorizationRequest({
      authorizationRequestPayload: {
        ...authenticatedRequest,
        presentation_definition: { id: 'pd', input_descriptors: [] },
      },
      callbacks,
      responseMode: { type: 'direct_post' },
    }).catch((error) => error)

    expect(error).toBeInstanceOf(Openid4vpAuthorizationRequestError)
    expect(error).toMatchObject({
      errorResponse: { error: 'invalid_request' },
      authorizationRequestPayload: { response_uri: responseUri },
    })
  })

  test('throws an Openid4vpAuthorizationRequestError for an invalid request from a client that is not authenticated', async () => {
    const error = await resolveOpenid4vpAuthorizationRequest({
      authorizationRequestPayload: {
        ...authenticatedRequest,
        client_id: 'redirect_uri:https://other.example.com/response_uri',
        presentation_definition: { id: 'pd', input_descriptors: [] },
      },
      callbacks,
      responseMode: { type: 'direct_post' },
    }).catch((error) => error)

    // The payload error takes precedence over the client error
    expect(error).toBeInstanceOf(Openid4vpAuthorizationRequestError)
    expect(error).toMatchObject({
      isClientAuthenticated: false,
      client: undefined,
      authorizationRequestPayload: { response_uri: responseUri },
      errorResponse: { error: 'invalid_request' },
    })
    expect(error.errorResponse.error_description).toContain('Exactly one of the following parameters')
  })

  test('throws an Openid4vpAuthorizationRequestError when the client cannot be authenticated', async () => {
    const error = await resolveOpenid4vpAuthorizationRequest({
      authorizationRequestPayload: {
        ...authenticatedRequest,
        client_id: 'redirect_uri:https://other.example.com/response_uri',
      },
      callbacks,
      responseMode: { type: 'direct_post' },
    }).catch((error) => error)

    expect(error).toBeInstanceOf(Openid4vpAuthorizationRequestError)
    expect(error).toMatchObject({
      isClientAuthenticated: false,
      errorResponse: { error: 'invalid_client' },
      authorizationRequestPayload: { response_uri: responseUri },
    })
  })

  test('throws an Openid4vpAuthorizationRequestError with the unverified request when the request object signature is invalid', async () => {
    const encode = (value: object) => encodeToBase64Url(JSON.stringify(value))
    const requestObject = `${encode({ alg: 'ES256', typ: 'oauth-authz-req+jwt', x5c: ['MIIB'] })}.${encode({
      ...authenticatedRequest,
      client_id: 'x509_san_dns:example.com',
    })}.c2lnbmF0dXJl`

    const error = await resolveOpenid4vpAuthorizationRequest({
      authorizationRequestPayload: { client_id: 'x509_san_dns:example.com', request: requestObject },
      callbacks: { ...callbacks, verifyJwt: () => ({ verified: false }) },
      responseMode: { type: 'direct_post' },
    }).catch((error) => error)

    expect(error).toBeInstanceOf(Openid4vpAuthorizationRequestError)
    expect(error).toMatchObject({
      isClientAuthenticated: false,
      jar: undefined,
      errorResponse: { error: 'invalid_request_object' },
      authorizationRequestPayload: { client_id: 'x509_san_dns:example.com', response_uri: responseUri },
    })
  })
})

describe('authorization error responses', () => {
  beforeAll(() => server.listen())
  afterEach(() => server.resetHandlers())
  afterAll(() => server.close())

  test('creates and submits an unencrypted error response', async () => {
    let receivedPayload: Record<string, unknown> | undefined
    server.resetHandlers(
      http.post(responseUri, async ({ request }) => {
        receivedPayload = Object.fromEntries((await request.formData()).entries())
        return HttpResponse.json({ redirect_uri: 'https://example.com/cb' })
      })
    )

    const response = await createOpenid4vpAuthorizationResponse({
      authorizationRequestPayload: authenticatedRequest,
      authorizationResponsePayload: { error: 'access_denied' },
      callbacks,
    })
    expect(response).toEqual({ authorizationResponsePayload: { error: 'access_denied', state: 'state' } })

    const { response: submissionResponse } = await submitOpenid4vpAuthorizationResponse({
      authorizationRequestPayload: authenticatedRequest,
      authorizationResponsePayload: response.authorizationResponsePayload,
      callbacks,
    })

    expect(receivedPayload).toEqual({ error: 'access_denied', state: 'state' })
    expect(() => parseOpenid4VpAuthorizationResponsePayload(receivedPayload ?? {})).toThrow(
      Openid4vpAuthorizationResponseError
    )
    expect(await submissionResponse.json()).toEqual({ redirect_uri: 'https://example.com/cb' })
  })

  test('creates and submits an error response for a request with an unsupported client identifier', async () => {
    let receivedPayload: Record<string, unknown> | undefined
    server.resetHandlers(
      http.post(responseUri, async ({ request }) => {
        receivedPayload = Object.fromEntries((await request.formData()).entries())
        return HttpResponse.json({})
      })
    )

    const error = await resolveOpenid4vpAuthorizationRequest({
      authorizationRequestPayload: { ...authenticatedRequest, client_id: 'unsupported_prefix:client' },
      callbacks,
      responseMode: { type: 'direct_post' },
    }).catch((error) => error)

    expect(error).toBeInstanceOf(Openid4vpAuthorizationRequestError)
    expect(error).toMatchObject({ isClientAuthenticated: false, errorResponse: { error: 'invalid_request' } })

    const authorizationRequestPayload = (error as Openid4vpAuthorizationRequestError).authorizationRequestPayload
    if (
      isOpenid4vpAuthorizationRequestDcApi(authorizationRequestPayload) ||
      isOpenid4vpAuthorizationRequestIae(authorizationRequestPayload)
    ) {
      throw new Error('Expected a direct_post authorization request')
    }

    const { authorizationResponsePayload } = await createOpenid4vpAuthorizationResponse({
      authorizationRequestPayload,
      authorizationResponsePayload: { error: error.errorResponse.error },
      callbacks,
    })
    await submitOpenid4vpAuthorizationResponse({ authorizationRequestPayload, authorizationResponsePayload, callbacks })

    expect(receivedPayload).toEqual({ error: 'invalid_request', state: 'state' })
  })

  test('creates an error response for an unsigned DC API request without an origin', async () => {
    const response = await createOpenid4vpAuthorizationResponse({
      authorizationRequestPayload: {
        response_type: 'vp_token',
        response_mode: 'dc_api',
        nonce: 'nonce',
        dcql_query: dcqlQuery,
      },
      authorizationResponsePayload: { error: 'access_denied' },
      callbacks,
    })

    expect(response).toEqual({ authorizationResponsePayload: { error: 'access_denied' } })
  })

  test('creates an unencrypted error response for a jarm response mode without jarm options', async () => {
    const response = await createOpenid4vpAuthorizationResponse({
      authorizationRequestPayload: { ...authenticatedRequest, response_mode: 'direct_post.jwt' },
      authorizationResponsePayload: { error: 'access_denied' },
      callbacks,
    })

    expect(response).toEqual({ authorizationResponsePayload: { error: 'access_denied', state: 'state' } })
  })

  test('still requires jarm options for a successful response with a jarm response mode', async () => {
    await expect(
      createOpenid4vpAuthorizationResponse({
        authorizationRequestPayload: { ...authenticatedRequest, response_mode: 'direct_post.jwt' },
        authorizationResponsePayload: { vp_token: { pid: ['presentation'] } },
        callbacks,
      })
    ).rejects.toThrow('Missing jarm options')
  })

  test('encrypts an error response', async () => {
    let encryptedPayload: unknown
    const response = await createOpenid4vpAuthorizationResponse({
      authorizationRequestPayload: {
        ...authenticatedRequest,
        response_mode: 'direct_post.jwt',
        client_metadata: { jwks: { keys: [encJwk] }, encrypted_response_enc_values_supported: ['A128GCM'] },
      },
      authorizationResponsePayload: { error: 'access_denied' },
      jarm: {
        encryption: { nonce: 'response-nonce' },
        serverMetadata: {
          authorization_signing_alg_values_supported: [],
          authorization_encryption_alg_values_supported: ['ECDH-ES'],
          authorization_encryption_enc_values_supported: ['A128GCM'],
        },
      },
      callbacks: {
        ...callbacks,
        encryptJwe: (_jweEncryptor, data) => {
          encryptedPayload = JSON.parse(data)
          return { encryptionJwk: encJwk, jwe: 'jwe' }
        },
      },
    })

    expect(encryptedPayload).toEqual({ error: 'access_denied', state: 'state' })
    expect(response.jarm?.responseJwt).toBe('jwe')
  })
})
