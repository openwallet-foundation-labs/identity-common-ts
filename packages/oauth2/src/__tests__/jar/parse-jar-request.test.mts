import { describe, expect, test, vi } from 'vitest'
import { Oauth2ServerErrorResponseError } from '../../error/Oauth2ServerErrorResponseError'
import { parseJarRequest } from '../../jar/handle-jar-request/verify-jar-request'

describe('parseJarRequest', () => {
  test.each([
    'urn:ietf:params:oauth:request_uri:abc',
    'http://169.254.169.254/latest/meta-data/',
    'file:///etc/passwd',
  ])("does not fetch non https request_uri '%s'", async (requestUri) => {
    const fetch = vi.fn()

    const error = await parseJarRequest({
      jarRequestParams: { client_id: 'x', request_uri: requestUri },
      callbacks: { fetch },
      allowRequestUri: true,
    }).catch((error) => error)

    expect(error).toBeInstanceOf(Oauth2ServerErrorResponseError)
    expect(error.errorResponse.error).toEqual('invalid_request_uri')
    expect(fetch).not.toHaveBeenCalled()
  })

  test('does not fetch request_uri by default', async () => {
    const fetch = vi.fn()

    await expect(
      parseJarRequest({
        jarRequestParams: { client_id: 'x', request_uri: 'https://attacker.example.com/request.jwt' },
        callbacks: { fetch },
      })
    ).rejects.toThrow('request_uri is not allowed')
    expect(fetch).not.toHaveBeenCalled()
  })

  test('does not fetch request_uri when allowRequestUri is false', async () => {
    const fetch = vi.fn()

    await expect(
      parseJarRequest({
        jarRequestParams: { client_id: 'x', request_uri: 'https://attacker.example.com/request.jwt' },
        callbacks: { fetch },
        allowRequestUri: false,
      })
    ).rejects.toThrow('request_uri is not allowed')
    expect(fetch).not.toHaveBeenCalled()
  })
})
