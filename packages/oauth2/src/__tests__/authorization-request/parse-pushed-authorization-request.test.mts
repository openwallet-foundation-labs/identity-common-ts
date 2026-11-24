import { JoseParseError } from '@owf/jose'
import { describe, expect, test, vi } from 'vitest'
import {
  parsePushedAuthorizationRequest,
  parsePushedAuthorizationRequestUriReferenceValue,
} from '../../authorization-request/parse-pushed-authorization-request'
import { Oauth2ServerErrorResponseError } from '../../error/Oauth2ServerErrorResponseError'

describe('Parse Pushed Authorization Response', () => {
  describe(`parsePushedAuthorizationRequestUriReferenceValue`, () => {
    test('parses valid uri', () => {
      expect(
        parsePushedAuthorizationRequestUriReferenceValue({
          uri: 'urn:ietf:params:oauth:request_uri:mamma-mia',
        })
      ).toEqual('mamma-mia')
    })

    test('throws on invalid uri', () => {
      expect(() =>
        parsePushedAuthorizationRequestUriReferenceValue({
          uri: 'foo bar',
        })
      ).toThrow(`The 'request_uri' must start with the prefix "urn:ietf:params:oauth:request_uri:".`)
    })
  })

  describe('parsePushedAuthorizationRequest', () => {
    test.each([
      'https://attacker.example.com/request.jwt',
      'http://169.254.169.254/latest/meta-data/',
      'urn:ietf:params:oauth:request_uri:abc',
    ])("rejects a request containing request_uri '%s' without fetching it", async (requestUri) => {
      const fetch = vi.fn()

      const error = await parsePushedAuthorizationRequest({
        request: { headers: new Headers(), method: 'POST', url: 'https://as.example.com/par' },
        authorizationRequest: {
          response_type: 'code',
          client_id: 'x',
          redirect_uri: 'https://client.example.com/cb',
          request_uri: requestUri,
        },
        callbacks: { fetch },
      }).catch((error) => error)

      expect(error).toBeInstanceOf(Oauth2ServerErrorResponseError)
      expect(error.errorResponse).toEqual({
        error: 'invalid_request',
        error_description: `The 'request_uri' parameter must not be provided in a pushed authorization request.`,
      })
      expect(fetch).not.toHaveBeenCalled()
    })

    // RFC 9126 Section 2.3: the error response of the token endpoint (RFC 6749 Section 5.2), with invalid_request.
    // The error_description is one line, as RFC 6749 Section 5.2 doesn't allow line breaks and quotes.
    test('throws invalid_request for a request that is neither an authorization request nor a jar', async () => {
      const error = await parsePushedAuthorizationRequest({
        request: { headers: new Headers(), method: 'POST', url: 'https://as.example.com/par' },
        authorizationRequest: { response_type: 'code' },
        callbacks: {},
      }).catch((error) => error)

      expect(error).toBeInstanceOf(Oauth2ServerErrorResponseError)
      expect(error.errorResponse).toEqual({
        error: 'invalid_request',
        error_description: 'Invalid authorization request. Could not parse authorization request or jar.',
      })
      expect(error.message).toContain('\n  - ')
    })

    // RFC 9101 Section 7: invalid_request_object for a request parameter with an invalid request object
    test('throws invalid_request_object for a jar whose request is not a jwt', async () => {
      const error = await parsePushedAuthorizationRequest({
        request: { headers: new Headers(), method: 'POST', url: 'https://as.example.com/par' },
        authorizationRequest: { client_id: 'x', request: 'not-a-jwt' },
        callbacks: {},
      }).catch((error) => error)

      expect(error).toBeInstanceOf(Oauth2ServerErrorResponseError)
      expect(error.errorResponse).toEqual({
        error: 'invalid_request_object',
        error_description: 'JAR request object is not a valid JWT.',
      })
      expect(error.cause).toBeInstanceOf(JoseParseError)
    })

    test('throws invalid_request_object for a jar whose request is encrypted', async () => {
      const error = await parsePushedAuthorizationRequest({
        request: { headers: new Headers(), method: 'POST', url: 'https://as.example.com/par' },
        authorizationRequest: {
          client_id: 'x',
          // A compact JWE with the header {"alg":"RSA-OAEP","enc":"A256GCM"}
          request: 'eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ.ZW5j.aXY.Y2lwaGVy.dGFn',
        },
        callbacks: {},
      }).catch((error) => error)

      expect(error).toBeInstanceOf(Oauth2ServerErrorResponseError)
      expect(error.errorResponse).toEqual({
        error: 'invalid_request_object',
        error_description: 'Encrypted JWE request objects are not supported.',
      })
    })

    test('throws invalid_request_object for a jar whose payload is not an authorization request', async () => {
      const error = await parsePushedAuthorizationRequest({
        request: { headers: new Headers(), method: 'POST', url: 'https://as.example.com/par' },
        authorizationRequest: {
          client_id: 'x',
          // A JWT with the payload {"client_id":"x"}, without response_type. The signature is not verified when parsing.
          request: 'eyJhbGciOiJFUzI1NiIsInR5cCI6Im9hdXRoLWF1dGh6LXJlcStqd3QifQ.eyJjbGllbnRfaWQiOiJ4In0.c2ln',
        },
        callbacks: {},
      }).catch((error) => error)

      expect(error).toBeInstanceOf(Oauth2ServerErrorResponseError)
      expect(error.errorResponse).toEqual({
        error: 'invalid_request_object',
        error_description: 'Invalid authorization request. Could not parse jar request payload.',
      })
    })
  })
})
