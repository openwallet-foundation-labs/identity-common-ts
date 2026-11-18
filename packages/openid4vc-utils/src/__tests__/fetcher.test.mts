import { CommonMediaTypes, IdentityCommonError } from '@owf/identity-common'
import { describe, expect, test } from 'vitest'
import z from 'zod'
import { FetchError } from '../error/FetchError.js'
import { InvalidFetchResponseError } from '../error/InvalidFetchResponseError.js'
import { createFetcher, createZodFetcher, type Fetch } from '../fetcher.js'

function createRecordingFetch() {
  const acceptHeaders: Array<string | null> = []
  const fetch: Fetch = async (_input, init) => {
    acceptHeaders.push(new Headers(init?.headers).get('Accept'))
    return Response.json({ hello: 'world' })
  }

  return { fetch, acceptHeaders }
}

describe('createZodFetcher', () => {
  test('sends the expected content types as the Accept header in order of preference', async () => {
    const { fetch, acceptHeaders } = createRecordingFetch()
    const fetchWithZod = createZodFetcher({ fetch }, 'jwks')

    await fetchWithZod(z.object({ hello: z.string() }), CommonMediaTypes.Json, 'https://example.com')
    await fetchWithZod(
      z.object({ hello: z.string() }),
      [CommonMediaTypes.Jwt, CommonMediaTypes.Json],
      'https://example.com',
      {
        headers: { 'Content-Type': CommonMediaTypes.Json },
      }
    )

    await fetchWithZod(
      z.object({ hello: z.string() }),
      [CommonMediaTypes.Jwt, CommonMediaTypes.JwkSet, CommonMediaTypes.Json],
      'https://example.com'
    )

    expect(acceptHeaders).toEqual([
      'application/json',
      'application/jwt, application/json;q=0.9',
      'application/jwt, application/jwk-set+json;q=0.9, application/json;q=0.8',
    ])
  })

  test('keeps an Accept header set by the caller', async () => {
    const { fetch, acceptHeaders } = createRecordingFetch()
    const fetchWithZod = createZodFetcher({ fetch }, 'jwks')

    await fetchWithZod(z.object({ hello: z.string() }), CommonMediaTypes.Json, 'https://example.com', {
      headers: new Headers({ Accept: 'application/json;q=0.9' }),
    })

    expect(acceptHeaders).toEqual(['application/json;q=0.9'])
  })

  test.each(['application/json-seq', 'multipart/related; type="application/json"'])(
    'rejects a lookalike response Content-Type: %s',
    async (contentType) => {
      const fetchWithZod = createZodFetcher(
        { fetch: async () => new Response('{"hello":"world"}', { headers: { 'Content-Type': contentType } }) },
        'jwks'
      )

      await expect(
        fetchWithZod(z.object({ hello: z.string() }), CommonMediaTypes.Json, 'https://example.com')
      ).rejects.toThrow('Expected response to match content type application/json')
    }
  )

  test.each(['application/json; charset=UTF-8', 'Application/JSON'])(
    'accepts a matching response Content-Type: %s',
    async (contentType) => {
      const fetchWithZod = createZodFetcher(
        { fetch: async () => new Response('{"hello":"world"}', { headers: { 'Content-Type': contentType } }) },
        'jwks'
      )

      await expect(
        fetchWithZod(z.object({ hello: z.string() }), CommonMediaTypes.Json, 'https://example.com')
      ).resolves.toMatchObject({ result: { success: true, data: { hello: 'world' } } })
    }
  )

  // The URL can be chosen by whoever sent the request, and the message may be returned to them, which would let them
  // read the responses of internal endpoints
  test('keeps the response body out of the error message for invalid JSON', async () => {
    const body = 'root:x:0:0:internal-secret'
    const fetchWithZod = createZodFetcher(
      { fetch: async () => new Response(body, { headers: { 'Content-Type': 'application/json' } }) },
      'jwks'
    )

    const error = await fetchWithZod(z.object({}), CommonMediaTypes.Json, 'https://example.com').catch((error) => error)

    expect(error).toBeInstanceOf(InvalidFetchResponseError)
    expect(error.message).not.toContain('internal-secret')
    expect(error.textResponse).toBe(body)
  })

  test('keeps the response body out of the error message for another content type', async () => {
    const fetchWithZod = createZodFetcher(
      { fetch: async () => new Response('root:x:0:0:internal-secret', { headers: { 'Content-Type': 'text/plain' } }) },
      'jwks'
    )

    const error = await fetchWithZod(z.object({}), CommonMediaTypes.Json, 'https://example.com').catch((error) => error)

    expect(error).toBeInstanceOf(IdentityCommonError)
    expect(error.message).not.toContain('internal-secret')
  })
})

describe('createFetcher', () => {
  test('tells the fetch what it fetches, and sends a URLSearchParams body as a string', async () => {
    const requests: Array<{ url: string; body: unknown; type: string }> = []
    const fetch: Fetch = async (url, init, { type }) => {
      requests.push({ url, body: init.body, type })
      return new Response(null, { status: 204 })
    }

    await createFetcher({ fetch }, 'notificationRequest')('https://example.com/notification', {
      method: 'POST',
      body: new URLSearchParams({ event: 'credential_accepted' }),
    })

    expect(requests).toEqual([
      { url: 'https://example.com/notification', body: 'event=credential_accepted', type: 'notificationRequest' },
    ])
  })

  test('rejects a response larger than the limit of its type', async () => {
    const fetch: Fetch = async () => new Response('a'.repeat(101))

    await expect(
      createFetcher(
        { fetch, fetchLimits: { maxResponseBytesByType: { credentialRequest: 100 } } },
        'credentialRequest'
      )('https://example.com/credential')
    ).rejects.toThrow(new IdentityCommonError('The response is larger than the maximum of 100 bytes'))
    await expect(
      createFetcher(
        { fetch, fetchLimits: { maxResponseBytesByType: { credentialRequest: 100 } } },
        'nonceRequest'
      )('https://example.com/nonce')
    ).resolves.toBeInstanceOf(Response)
  })

  test('wraps an error of the fetch in a FetchError', async () => {
    const fetch: Fetch = async () => {
      throw new TypeError('fetch failed')
    }

    await expect(createFetcher({ fetch }, 'nonceRequest')('https://example.com/nonce')).rejects.toThrow(FetchError)
  })
})
