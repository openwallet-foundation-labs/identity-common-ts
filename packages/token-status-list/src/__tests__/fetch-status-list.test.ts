import { describe, expect, it } from 'vitest'
import { fetchStatusList } from '../fetch-status-list'
import { SLException } from '../status-list-exception'
import { MediaTypes } from '../types'

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
      customFetcher: fetcherWithContentType(`${MediaTypes.StatusListCwt}; charset=binary`, new Uint8Array([1, 2, 3])),
    })

    expect(statusList).toStrictEqual(new Uint8Array([1, 2, 3]))
  })

  it.each([
    { acceptedFormats: undefined, accept: `${MediaTypes.StatusListJwt},${MediaTypes.StatusListCwt};q=0.9` },
    {
      acceptedFormats: ['cwt', 'jwt'] as const,
      accept: `${MediaTypes.StatusListCwt},${MediaTypes.StatusListJwt};q=0.9`,
    },
    { acceptedFormats: ['cwt'] as const, accept: MediaTypes.StatusListCwt },
    {
      acceptedFormats: ['cwt', 'cwt', 'jwt'] as const,
      accept: `${MediaTypes.StatusListCwt},${MediaTypes.StatusListJwt};q=0.9`,
    },
  ])('should prefer the first of $acceptedFormats in the Accept header', async ({ acceptedFormats, accept }) => {
    let sentAccept: string | null = null
    const customFetcher = (async (_uri: string, init?: RequestInit) => {
      sentAccept = new Headers(init?.headers).get('Accept')
      return new Response('a.b.c', { status: 200, headers: { 'Content-Type': MediaTypes.StatusListJwt } })
    }) as unknown as typeof fetch

    await fetchStatusList({
      uri: 'https://example.org/statuslists/1',
      customFetcher,
      acceptedFormats: acceptedFormats ? [...acceptedFormats] : undefined,
    })

    expect(sentAccept).toBe(accept)
  })

  it('should throw when the content type is not a status list media type', async () => {
    await expect(
      fetchStatusList({
        uri: 'https://example.org/statuslists/1',
        customFetcher: fetcherWithContentType('application/json'),
      })
    ).rejects.toThrow(SLException)
  })
})
