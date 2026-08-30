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

  it('should throw when the content type is not a status list media type', async () => {
    await expect(
      fetchStatusList({
        uri: 'https://example.org/statuslists/1',
        customFetcher: fetcherWithContentType('application/json'),
      })
    ).rejects.toThrow(SLException)
  })
})
