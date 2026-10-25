import { describe, expect, test } from 'vitest'
import z from 'zod'
import { ContentType } from '../content-type.js'
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

    await fetchWithZod(z.object({ hello: z.string() }), ContentType.Json, 'https://example.com')
    await fetchWithZod(z.object({ hello: z.string() }), [ContentType.Jwt, ContentType.Json], 'https://example.com', {
      headers: { 'Content-Type': ContentType.Json },
    })

    await fetchWithZod(
      z.object({ hello: z.string() }),
      [ContentType.Jwt, ContentType.JwkSet, ContentType.Json],
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

    await fetchWithZod(z.object({ hello: z.string() }), ContentType.Json, 'https://example.com', {
      headers: new Headers({ Accept: 'application/json;q=0.9' }),
    })

    expect(acceptHeaders).toEqual(['application/json;q=0.9'])
  })
})
