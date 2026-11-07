import { CommonMediaTypes } from '@owf/identity-common'
import { describe, expect, test } from 'vitest'
import z from 'zod'
import { InvalidFetchResponseError } from '../error/InvalidFetchResponseError.js'
import { createZodFetcher } from '../fetcher.js'
import type { Fetch } from '../globals.js'

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
    const fetchWithZod = createZodFetcher(fetch)

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
    const fetchWithZod = createZodFetcher(fetch)

    await fetchWithZod(z.object({ hello: z.string() }), CommonMediaTypes.Json, 'https://example.com', {
      headers: new Headers({ Accept: 'application/json;q=0.9' }),
    })

    expect(acceptHeaders).toEqual(['application/json;q=0.9'])
  })

  test.each(['application/json-seq', 'multipart/related; type="application/json"'])(
    'rejects a lookalike response Content-Type: %s',
    async (contentType) => {
      const fetchWithZod = createZodFetcher(
        async () => new Response('{"hello":"world"}', { headers: { 'Content-Type': contentType } })
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
        async () => new Response('{"hello":"world"}', { headers: { 'Content-Type': contentType } })
      )

      await expect(
        fetchWithZod(z.object({ hello: z.string() }), CommonMediaTypes.Json, 'https://example.com')
      ).resolves.toMatchObject({ result: { success: true, data: { hello: 'world' } } })
    }
  )

  // The URL can be chosen by whoever sent the request, and the message may be returned to them, which would let them
  // read the responses of internal endpoints
  test.each([
    ['another content type', 'text/plain'],
    ['invalid JSON', 'application/json'],
  ])('keeps the response body out of the error message for %s', async (_description, contentType) => {
    const body = 'root:x:0:0:internal-secret'
    const fetchWithZod = createZodFetcher(async () => new Response(body, { headers: { 'Content-Type': contentType } }))

    const error = await fetchWithZod(z.object({}), CommonMediaTypes.Json, 'https://example.com').catch((error) => error)

    expect(error).toBeInstanceOf(InvalidFetchResponseError)
    expect(error.message).not.toContain('internal-secret')
    expect(error.textResponse).toBe(body)
  })
})
