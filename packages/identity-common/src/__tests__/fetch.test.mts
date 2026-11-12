import { afterEach, describe, expect, it, vi } from 'vitest'
import { type FetchCallback, type FetchLimits, fetchAndParse, fetchWithLimits, IdentityCommonError } from '../../src'

const MiB = 1024 * 1024

/** A fetch callback that answers every request with `response`, recording its calls. */
const fetchReturning = (response: () => Response) => vi.fn<FetchCallback>(async () => response())

/** A response that claims `length` bytes, so a limit can be tested without a body of that size. */
const withContentLength = (length: number) => () =>
  new Response('{}', { headers: { 'Content-Length': String(length), 'Content-Type': 'application/json' } })

describe('fetchWithLimits', () => {
  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('passes what is fetched to the fetch callback, and asks for the media types in order of preference', async () => {
    const fetch = fetchReturning(() => new Response('{}'))

    await fetchWithLimits(
      { fetch },
      {
        type: 'statusList',
        url: 'https://example.com/statuslists/1',
        init: { method: 'GET', headers: { 'X-Custom': 'value' } },
        accept: ['application/statuslist+jwt', 'application/statuslist+cwt'],
      }
    )

    expect(fetch).toHaveBeenCalledOnce()
    const [url, init, context] = fetch.mock.calls[0]
    expect(url).toBe('https://example.com/statuslists/1')
    expect(init.method).toBe('GET')
    expect(new Headers(init.headers).get('X-Custom')).toBe('value')
    expect(new Headers(init.headers).get('Accept')).toBe('application/statuslist+jwt, application/statuslist+cwt;q=0.9')
    expect(context).toEqual({ type: 'statusList' })
  })

  it('keeps the headers of a Headers of another implementation', async () => {
    const fetch = fetchReturning(() => new Response('{}'))
    // As the Headers of a polyfill, which the global Headers does not know
    const headers = {
      forEach: (callback: (value: string, name: string) => void) => {
        callback('application/x-www-form-urlencoded', 'Content-Type')
        callback('proof', 'DPoP')
      },
    } as unknown as Headers

    await fetchWithLimits(
      { fetch },
      { type: 'accessTokenRequest', url: 'https://example.com/token', init: { headers } }
    )

    expect(Object.fromEntries(new Headers(fetch.mock.calls[0][1].headers))).toEqual({
      'content-type': 'application/x-www-form-urlencoded',
      dpop: 'proof',
    })
  })

  it('keeps an Accept header that the request sets', async () => {
    const fetch = fetchReturning(() => new Response('{}'))

    await fetchWithLimits(
      { fetch },
      {
        type: 'jwks',
        url: 'https://example.com/jwks',
        init: { headers: { Accept: 'text/plain' } },
        accept: 'application/json',
      }
    )

    expect(new Headers(fetch.mock.calls[0][1].headers).get('Accept')).toBe('text/plain')
  })

  it('uses the global fetch by default, resolved when it is called', async () => {
    const fetch = vi.fn(async () => new Response('hello'))
    vi.stubGlobal('fetch', fetch)

    const response = await fetchWithLimits({}, { type: 'requestObject', url: 'https://example.com/request' })

    await expect(response.text()).resolves.toBe('hello')
    expect(fetch).toHaveBeenCalledOnce()
  })

  it.each<[string, number | undefined, number]>([
    ['10 MiB', undefined, 10 * MiB],
    ['the default of the library', 16 * MiB, 16 * MiB],
  ])('limits a response to %s by default', async (_, defaultMaxResponseBytes, limit) => {
    const request = { type: 'statusList', url: 'https://example.com', defaultMaxResponseBytes }

    await expect(fetchWithLimits({ fetch: fetchReturning(withContentLength(limit)) }, request)).resolves.toBeInstanceOf(
      Response
    )
    await expect(fetchWithLimits({ fetch: fetchReturning(withContentLength(limit + 1)) }, request)).rejects.toThrow(
      new IdentityCommonError(`The response is larger than the maximum of ${limit} bytes`)
    )
  })

  it.each<[string, FetchLimits<'statusList' | 'jwks'>, 'statusList' | 'jwks', number]>([
    ['the global limit over the default of the library', { maxResponseBytes: 1000 }, 'statusList', 1000],
    [
      'the limit of the type over the global limit',
      { maxResponseBytes: 1000, maxResponseBytesByType: { statusList: 2000 } },
      'statusList',
      2000,
    ],
    [
      'the global limit for a type without a limit of its own',
      { maxResponseBytes: 1000, maxResponseBytesByType: { statusList: 2000 } },
      'jwks',
      1000,
    ],
    [
      'the limit of the type over the default of the library',
      { maxResponseBytesByType: { statusList: MiB } },
      'statusList',
      MiB,
    ],
  ])('applies %s', async (_, fetchLimits, type, limit) => {
    const request = { type, url: 'https://example.com', defaultMaxResponseBytes: 16 * MiB }

    await expect(
      fetchWithLimits({ fetch: fetchReturning(withContentLength(limit)), fetchLimits }, request)
    ).resolves.toBeInstanceOf(Response)
    await expect(
      fetchWithLimits({ fetch: fetchReturning(withContentLength(limit + 1)), fetchLimits }, request)
    ).rejects.toThrow(`The response is larger than the maximum of ${limit} bytes`)
  })

  it('stops reading a streamed body once it is larger than the limit', async () => {
    let pulled = 0
    const body = new ReadableStream<Uint8Array>(
      {
        pull: (controller) => {
          pulled++
          controller.enqueue(new Uint8Array(1024))
        },
      },
      { highWaterMark: 0 }
    )

    await expect(
      fetchWithLimits(
        { fetch: fetchReturning(() => new Response(body)), fetchLimits: { maxResponseBytes: 4096 } },
        { type: 'credentialRequest', url: 'https://example.com' }
      )
    ).rejects.toThrow('The response is larger than the maximum of 4096 bytes')
    expect(pulled).toBe(5)
  })

  it.each([Number.NaN, -1])('rejects a limit of %s before fetching', async (maxResponseBytes) => {
    const fetch = fetchReturning(() => new Response('{}'))

    await expect(
      fetchWithLimits(
        { fetch, fetchLimits: { maxResponseBytes } },
        { type: 'nonceRequest', url: 'https://example.com' }
      )
    ).rejects.toThrow(
      new IdentityCommonError(
        `The maximum size of a nonceRequest response must be a number of 0 or more, but is ${maxResponseBytes}`
      )
    )
    expect(fetch).not.toHaveBeenCalled()
  })

  it('passes an error of the fetch callback on', async () => {
    const error = new TypeError('fetch failed')

    await expect(
      fetchWithLimits(
        {
          fetch: async () => {
            throw error
          },
        },
        { type: 'jwks', url: 'https://example.com' }
      )
    ).rejects.toBe(error)
  })

  it('returns a response that holds the body, with the status, headers, url and redirect of the response', async () => {
    const fetched = new Response('{"keys":[]}', {
      status: 201,
      statusText: 'Created',
      headers: { 'Content-Type': 'application/json', 'Content-Encoding': 'gzip', 'Content-Length': '11' },
    })
    Object.defineProperties(fetched, {
      url: { value: 'https://example.com/redirected' },
      redirected: { value: true },
    })

    const response = await fetchWithLimits({ fetch: async () => fetched }, { type: 'jwks', url: 'https://example.com' })

    expect(response.status).toBe(201)
    expect(response.statusText).toBe('Created')
    expect(response.url).toBe('https://example.com/redirected')
    expect(response.redirected).toBe(true)
    expect(response.headers.get('Content-Type')).toBe('application/json')
    expect(response.headers.has('Content-Encoding')).toBe(false)
    expect(response.headers.has('Content-Length')).toBe(false)
    await expect(response.clone().text()).resolves.toBe('{"keys":[]}')
    await expect(response.json()).resolves.toEqual({ keys: [] })
  })

  it('returns a response without a body for a status that cannot have one', async () => {
    const response = await fetchWithLimits(
      { fetch: async () => new Response(null, { status: 204 }) },
      { type: 'notificationRequest', url: 'https://example.com' }
    )

    expect(response.status).toBe(204)
    expect(response.body).toBeNull()
  })
})

describe('fetchAndParse', () => {
  const json = (body: string, init?: ResponseInit) => () =>
    new Response(body, { ...init, headers: { 'Content-Type': 'application/json', ...init?.headers } })

  it('parses the body of a response with a 2xx status and an accepted media type', async () => {
    const parse = vi.fn((body: Uint8Array) => JSON.parse(new TextDecoder().decode(body)))

    const result = await fetchAndParse(
      { fetch: fetchReturning(json('{"keys":[]}')) },
      { type: 'jwks', url: 'https://example.com', accept: ['application/jwk-set+json', 'application/json'], parse }
    )

    expect(result.data).toEqual({ keys: [] })
    expect(result.response.status).toBe(200)
    expect(parse).toHaveBeenCalledWith(new TextEncoder().encode('{"keys":[]}'), result.response)
  })

  it('parses into a class instance', async () => {
    class Token {
      public constructor(public readonly bytes: Uint8Array) {}
    }

    const result = await fetchAndParse(
      { fetch: fetchReturning(() => new Response(new Uint8Array([1, 2, 3]))) },
      { type: 'identifierList', url: 'https://example.com', parse: (body) => new Token(body) }
    )

    expect(result.data).toEqual(new Token(new Uint8Array([1, 2, 3])))
  })

  it('does not parse a response with another status, and keeps its body', async () => {
    const parse = vi.fn()

    const result = await fetchAndParse(
      { fetch: fetchReturning(json('{"error":"invalid_request"}', { status: 400 })) },
      { type: 'accessTokenRequest', url: 'https://example.com', accept: 'application/json', parse }
    )

    expect(result.data).toBeUndefined()
    expect(result.response.status).toBe(400)
    await expect(result.response.json()).resolves.toEqual({ error: 'invalid_request' })
    expect(parse).not.toHaveBeenCalled()
  })

  it('rejects a response with a 2xx status of another media type than accepted, without its body', async () => {
    const parse = vi.fn()

    const error = await fetchAndParse(
      { fetch: fetchReturning(() => new Response('internal-secret', { headers: { 'Content-Type': 'text/html' } })) },
      { type: 'clientMetadata', url: 'https://example.com', accept: ['application/jwt', 'application/json'], parse }
    ).catch((error) => error)

    expect(error).toEqual(
      new IdentityCommonError(
        "Expected response to match content type application/jwt | application/json, but received 'text/html'"
      )
    )
    expect(error.message).not.toContain('internal-secret')
    expect(parse).not.toHaveBeenCalled()
  })

  it('returns a response with another status of any media type', async () => {
    const result = await fetchAndParse(
      {
        fetch: fetchReturning(
          () => new Response('<html></html>', { status: 502, headers: { 'Content-Type': 'text/html' } })
        ),
      },
      { type: 'clientMetadata', url: 'https://example.com', accept: 'application/json', parse: vi.fn() }
    )

    expect(result.data).toBeUndefined()
    expect(result.response.status).toBe(502)
  })

  it('passes an error of parse on', async () => {
    const error = new Error('invalid')

    await expect(
      fetchAndParse(
        { fetch: fetchReturning(json('{}')) },
        {
          type: 'jwks',
          url: 'https://example.com',
          parse: () => {
            throw error
          },
        }
      )
    ).rejects.toBe(error)
  })
})
