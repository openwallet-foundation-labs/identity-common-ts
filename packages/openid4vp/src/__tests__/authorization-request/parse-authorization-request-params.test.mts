import { Oauth2ServerErrorResponseError } from '@openid4vc/oauth2'
import { describe, expect, test } from 'vitest'
import { parseOpenid4vpAuthorizationRequest } from '../../authorization-request/parse-authorization-request-params.js'

describe('Parse Authorization Request Params', () => {
  test('parse authorization request uri and transforms string JSON fields to JSON', () => {
    expect(
      parseOpenid4vpAuthorizationRequest({
        authorizationRequest: `openid4vp://?response_type=vp_token&client_id=test&nonce=nonce&presentation_definition=${encodeURIComponent(JSON.stringify({ id: 'something' }))}&dcql_query=${encodeURIComponent(JSON.stringify({ id: 'something' }))}&client_metadata=${encodeURIComponent(JSON.stringify({ my: 'metadata' }))}&transaction_data=${encodeURIComponent(JSON.stringify(['c29tZXRoaW5n']))}&verifier_attestations=${encodeURIComponent(JSON.stringify([{ format: 'custom', data: 'none', credential_ids: ['my-id'] }]))}&verifier_info=${encodeURIComponent(JSON.stringify([{ format: 'custom', data: 'none', credential_ids: ['my-id'] }]))}`,
      })
    ).toEqual({
      type: 'openid4vp',
      provided: 'uri',
      params: {
        response_type: 'vp_token',
        client_id: 'test',
        nonce: 'nonce',
        presentation_definition: { id: 'something' },
        client_metadata: { my: 'metadata' },
        dcql_query: { id: 'something' },
        transaction_data: ['c29tZXRoaW5n'],
        verifier_attestations: [
          {
            format: 'custom',
            data: 'none',
            credential_ids: ['my-id'],
          },
        ],
        verifier_info: [
          {
            format: 'custom',
            data: 'none',
            credential_ids: ['my-id'],
          },
        ],
      },
    })
  })

  const uriRequest = (params: Record<string, string>) =>
    `openid4vp://?${new URLSearchParams({ response_type: 'vp_token', nonce: 'nonce', ...params }).toString()}`

  test('parses an unsigned uri request with a redirect_uri client id', () => {
    expect(
      parseOpenid4vpAuthorizationRequest({
        authorizationRequest: uriRequest({
          client_id: 'redirect_uri:https://verifier.example.com/cb',
          response_mode: 'direct_post',
          response_uri: 'https://verifier.example.com/cb',
        }),
      })
    ).toMatchObject({ type: 'openid4vp', provided: 'uri' })
  })

  test('parses an unsigned uri request with a legacy redirect_uri client_id_scheme', () => {
    expect(
      parseOpenid4vpAuthorizationRequest({
        authorizationRequest: uriRequest({
          client_id: 'https://verifier.example.com/cb',
          client_id_scheme: 'redirect_uri',
          response_mode: 'direct_post',
          response_uri: 'https://verifier.example.com/cb',
        }),
      })
    ).toMatchObject({ type: 'openid4vp', provided: 'uri' })
  })

  test('rejects an unsigned uri request with a client id prefix that requires a signed request (OpenID4VP 1.0 Section 5.9.3)', () => {
    expect(() =>
      parseOpenid4vpAuthorizationRequest({
        authorizationRequest: uriRequest({
          client_id: 'x509_san_dns:verifier.example.com',
          response_mode: 'direct_post',
          response_uri: 'https://verifier.example.com/cb',
        }),
      })
    ).toThrow(Oauth2ServerErrorResponseError)
  })

  test('accepts the same request with a client id prefix that requires signing when passed as an object', () => {
    expect(
      parseOpenid4vpAuthorizationRequest({
        authorizationRequest: {
          response_type: 'vp_token',
          nonce: 'nonce',
          client_id: 'x509_san_dns:verifier.example.com',
          response_mode: 'direct_post',
          response_uri: 'https://verifier.example.com/cb',
        },
      })
    ).toMatchObject({ type: 'openid4vp', provided: 'params' })
  })

  test('rejects a DC API request passed as a uri (OpenID4VP 1.0 Appendix A.2)', () => {
    expect(() =>
      parseOpenid4vpAuthorizationRequest({
        authorizationRequest: uriRequest({
          response_mode: 'dc_api',
          dcql_query: JSON.stringify({ credentials: [] }),
        }),
      })
    ).toThrow(/must be passed as a JSON object/)
  })

  test('parses a DC API request passed as an object (OpenID4VP 1.0 Appendix A.2)', () => {
    expect(
      parseOpenid4vpAuthorizationRequest({
        authorizationRequest: {
          response_type: 'vp_token',
          nonce: 'nonce',
          response_mode: 'dc_api',
          dcql_query: { credentials: [] },
        },
      })
    ).toMatchObject({ type: 'openid4vp_dc_api', provided: 'params' })
  })
})
