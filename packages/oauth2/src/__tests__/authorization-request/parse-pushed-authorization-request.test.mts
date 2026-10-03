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
  })
})
