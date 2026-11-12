import { describe, expect, test, vi } from 'vitest'
import { callbacks } from '../../../oauth2/src/__tests__/util.mjs'
import { resolveOpenid4vpAuthorizationRequest, zClientMetadata } from '../index.js'

// The client metadata URLs come from a request that is not authenticated yet, chosen by whoever crafted it
describe('client metadata URLs', () => {
  test('fetches the client_metadata_uri with the fetch of the wallet', async () => {
    const fetch = vi.fn(async () => new Response(null, { status: 404 }))

    await resolveOpenid4vpAuthorizationRequest({
      // A request of a draft before 21, which had client_metadata_uri
      authorizationRequestPayload: {
        response_type: 'vp_token',
        response_mode: 'direct_post',
        client_id: 'https://verifier.example/response',
        client_id_scheme: 'redirect_uri',
        response_uri: 'https://verifier.example/response',
        nonce: 'nonce',
        presentation_definition: { id: 'pd', input_descriptors: [] },
        client_metadata_uri: 'https://verifier.example/metadata',
      },
      callbacks: { ...callbacks, fetch },
      responseMode: { type: 'direct_post' },
    }).catch(() => undefined)

    expect(fetch).toHaveBeenCalledWith('https://verifier.example/metadata', expect.anything(), {
      type: 'clientMetadata',
    })
  })

  test('rejects a jwks_uri that is not an https url', () => {
    expect(zClientMetadata.safeParse({ jwks_uri: 'http://169.254.169.254/latest/meta-data/' }).success).toBe(false)
  })
})
