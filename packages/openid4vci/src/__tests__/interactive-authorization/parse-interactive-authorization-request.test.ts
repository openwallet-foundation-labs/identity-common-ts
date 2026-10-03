import { Oauth2ServerErrorResponseError } from '@openid4vc/oauth2'
import { describe, expect, test, vi } from 'vitest'
import { parseInteractiveAuthorizationRequest } from '../../interactive-authorization/parse-interactive-authorization-request'

describe('parseInteractiveAuthorizationRequest', () => {
  test.each([
    { client_id: 'x', request_uri: 'https://attacker.example.com/request.jwt' },
    { client_id: 'x', request_uri: 'http://169.254.169.254/latest/meta-data/' },
    { client_id: 'x', request_uri: 'urn:ietf:params:oauth:request_uri:abc', interaction_types_supported: 'openid4vp' },
  ])('rejects a request containing request_uri without fetching it (%o)', async (interactiveAuthorizationRequest) => {
    const fetch = vi.fn()

    const error = await parseInteractiveAuthorizationRequest({
      request: { headers: new Headers(), method: 'POST', url: 'https://as.example.com/iae' },
      interactiveAuthorizationRequest,
      callbacks: { fetch },
    }).catch((error) => error)

    expect(error).toBeInstanceOf(Oauth2ServerErrorResponseError)
    expect(error.errorResponse).toEqual({
      error: 'invalid_request',
      error_description: `The 'request_uri' parameter must not be provided in an interactive authorization request.`,
    })
    expect(fetch).not.toHaveBeenCalled()
  })
})
