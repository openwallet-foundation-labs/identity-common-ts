import { describe, expect, it, vi } from 'vitest'
import { fetchStatusList } from '../fetch-status-list'
import { StatusListError } from '../status-list-error'
import { StatusListMediaTypes } from '../types'

const fetcherWithContentType = (contentType: string, body: BodyInit = 'a.b.c'): typeof fetch =>
  (async () => new Response(body, { status: 200, headers: { 'Content-Type': contentType } })) as unknown as typeof fetch

describe('fetchStatusList', () => {
  it('should accept a jwt content type with parameters and different casing', async () => {
    const statusList = await fetchStatusList({
      uri: 'https://example.org/statuslists/1',
      customFetcher: fetcherWithContentType('Application/StatusList+JWT; charset=UTF-8'),
    })

    expect(statusList).toStrictEqual('a.b.c')
  })

  it('should accept a cwt content type with parameters', async () => {
    const statusList = await fetchStatusList({
      uri: 'https://example.org/statuslists/1',
      customFetcher: fetcherWithContentType(
        `${StatusListMediaTypes.StatusListCwt}; charset=binary`,
        new Uint8Array([1, 2, 3])
      ),
    })

    expect(statusList).toStrictEqual(new Uint8Array([1, 2, 3]))
  })

  it.each([
    {
      acceptedFormats: undefined,
      accept: `${StatusListMediaTypes.StatusListJwt}, ${StatusListMediaTypes.StatusListCwt};q=0.9`,
    },
    {
      acceptedFormats: ['cwt', 'jwt'] as const,
      accept: `${StatusListMediaTypes.StatusListCwt}, ${StatusListMediaTypes.StatusListJwt};q=0.9`,
    },
    { acceptedFormats: ['cwt'] as const, accept: StatusListMediaTypes.StatusListCwt },
    {
      acceptedFormats: ['cwt', 'cwt', 'jwt'] as const,
      accept: `${StatusListMediaTypes.StatusListCwt}, ${StatusListMediaTypes.StatusListJwt};q=0.9`,
    },
  ])('should prefer the first of $acceptedFormats in the Accept header', async ({ acceptedFormats, accept }) => {
    let sentAccept: string | null = null
    const customFetcher = (async (_uri: string, init?: RequestInit) => {
      sentAccept = new Headers(init?.headers).get('Accept')
      return new Response('a.b.c', { status: 200, headers: { 'Content-Type': StatusListMediaTypes.StatusListJwt } })
    }) as unknown as typeof fetch

    await fetchStatusList({
      uri: 'https://example.org/statuslists/1',
      customFetcher,
      acceptedFormats: acceptedFormats ? [...acceptedFormats] : undefined,
    })

    expect(sentAccept).toBe(accept)
  })

  describe('with a response larger than maxResponseBytes', () => {
    const uri = 'https://example.org/statuslists/1'
    const cwtHeaders = { 'Content-Type': StatusListMediaTypes.StatusListCwt }

    /** A body that streams `chunkCount` chunks of `chunkSize` bytes, counting the chunks it was asked for. */
    const streamedBody = (chunkSize: number, chunkCount = Number.POSITIVE_INFINITY) => {
      const stream = { pulled: 0, cancelled: false }
      const body = new ReadableStream<Uint8Array>(
        {
          pull: (controller) => {
            if (stream.pulled === chunkCount) return controller.close()
            stream.pulled++
            controller.enqueue(new Uint8Array(chunkSize))
          },
          cancel: () => {
            stream.cancelled = true
          },
        },
        { highWaterMark: 0 }
      )
      return { stream, body }
    }

    const fetchWith = (response: Response, maxResponseBytes?: number) =>
      fetchStatusList({ uri, customFetcher: (async () => response) as typeof fetch, maxResponseBytes })

    it('rejects the response by its Content-Length, before reading the body', async () => {
      const { stream, body } = streamedBody(1024)
      const response = new Response(body, { headers: { ...cwtHeaders, 'Content-Length': '4097' } })

      await expect(fetchWith(response, 4096)).rejects.toThrow('The response is larger than the maximum of 4096 bytes')
      expect(stream.pulled).toBe(0)
      expect(stream.cancelled).toBe(true)
    })

    it('stops reading a body without Content-Length once it is larger than the maximum', async () => {
      const { stream, body } = streamedBody(1024)

      await expect(fetchWith(new Response(body, { headers: cwtHeaders }), 4096)).rejects.toThrow(
        'The response is larger than the maximum of 4096 bytes'
      )
      expect(stream.pulled).toBe(5)
      expect(stream.cancelled).toBe(true)
    })

    it('stops reading a body larger than 16 MiB by default', async () => {
      const { stream, body } = streamedBody(1024 * 1024)

      await expect(fetchWith(new Response(body, { headers: cwtHeaders }))).rejects.toThrow(
        'The response is larger than the maximum of 16777216 bytes'
      )
      expect(stream.pulled).toBe(17)
    })

    it('reads a body of maxResponseBytes', async () => {
      const { body } = streamedBody(1024, 4)

      await expect(fetchWith(new Response(body, { headers: cwtHeaders }), 4096)).resolves.toEqual(new Uint8Array(4096))
    })

    // The fetch of React Native has no body stream
    it('rejects a body without a stream once it is read', async () => {
      const response = new Response(new Uint8Array(4097), {
        headers: { 'Content-Type': StatusListMediaTypes.StatusListJwt },
      })
      const arrayBuffer = vi.spyOn(response, 'arrayBuffer')
      Object.defineProperty(response, 'body', { value: null })

      await expect(fetchWith(response, 4096)).rejects.toThrow('The response is larger than the maximum of 4096 bytes')
      expect(arrayBuffer).toHaveBeenCalled()
    })
  })

  it('should throw when the content type is not a status list media type', async () => {
    await expect(
      fetchStatusList({
        uri: 'https://example.org/statuslists/1',
        customFetcher: fetcherWithContentType('application/json'),
      })
    ).rejects.toThrow(StatusListError)
  })
})
