import { CommonMediaTypes } from '@owf/identity-common'
import { type Jwk, type JwkSet, type JwsSigner, jwsHeaderFromSigner, signJwt } from '@owf/jose'
import { HttpResponse, http } from 'msw'
import { setupServer } from 'msw/node'
import { afterAll, afterEach, beforeAll, describe, expect, test } from 'vitest'
import { verifyIdTokenJwt } from '../../id-token/verify-id-token'
import type { AuthorizationServerMetadata } from '../../metadata/authorization-server/z-authorization-server-metadata'
import { callbacks, getSignJwsCallback } from '../util.mjs'

const server = setupServer()

const signerJwk = {
  kty: 'EC',
  d: 'Y2KgM6WsS5lAiZMj96VaqPm0YpP67mclJ5yXbhM7oQE',
  crv: 'P-256',
  x: 'kazsvNpTiwE4mB6k-uLHNfexl_UysiJqNvDRO6SZE1A',
  y: 'VnWF5YzCR5ZWiugFM4rxPDviOWmMXU4pUVCRAdz-uLI',
} satisfies Jwk
const { d: __1, ...signerJwkPublic } = signerJwk

const signer = {
  method: 'jwk',
  alg: 'ES256',
  publicJwk: signerJwkPublic,
} satisfies JwsSigner

const signJws = getSignJwsCallback([signerJwk])

const authorizationServerMetadata = {
  issuer: 'https://authorization-server.com',
  token_endpoint: 'https://authorization-server.com/token',
  jwks_uri: 'https://authorization-server.com/jwks.json',
} satisfies AuthorizationServerMetadata

describe('Verify ID Token JWT', () => {
  beforeAll(() => {
    server.listen()
  })

  afterEach(() => {
    server.resetHandlers()
  })

  afterAll(() => {
    server.close()
  })

  describe(`valid token`, async () => {
    const header = {
      ...jwsHeaderFromSigner(signer),
      alg: 'ES256',
      typ: 'JWT',
    }

    const payload = {
      iss: authorizationServerMetadata.issuer,
      aud: ['my-client-id'],
      exp: Math.floor(Date.now() / 1000) + 3600,
      iat: Math.floor(Date.now() / 1000),
      sub: 'user-123',
      name: 'John Doe',
      nickname: 'marmite',
      website: 'https://example.com',
    }

    const { jwt } = await signJwt({ header, payload, signer: signer, signJwsCallback: signJws })

    server.resetHandlers(
      http.get(authorizationServerMetadata.jwks_uri, () =>
        HttpResponse.json({ keys: [signerJwkPublic] } satisfies JwkSet, {
          headers: { 'Content-Type': CommonMediaTypes.JwkSet },
        })
      )
    )

    test('resolves when parameters are correct', async () => {
      await expect(
        verifyIdTokenJwt({
          idToken: jwt,
          clientId: 'my-client-id',
          callbacks: {
            verifyJws: callbacks.verifyJws,
            fetch,
          },
          authorizationServer: authorizationServerMetadata,
        })
      ).resolves.toMatchObject({
        header,
        payload,
      })
    })

    test('rejects when clientId is unexpected', async () => {
      await expect(
        verifyIdTokenJwt({
          idToken: jwt,
          clientId: 'mamma-mia',
          callbacks: {
            verifyJws: callbacks.verifyJws,
            fetch,
          },
          authorizationServer: authorizationServerMetadata,
        })
      ).rejects.toThrow(`The 'aud' claim 'my-client-id' does not match the expected value 'mamma-mia'`)
    })
  })

  test('passes the kid of the id token to the getJwks callback', async () => {
    const kidSigner = { method: 'custom', alg: 'ES256', kid: 'key-1' } satisfies JwsSigner
    const { jwt } = await signJwt({
      header: { ...jwsHeaderFromSigner(kidSigner), typ: 'JWT' },
      payload: {
        iss: authorizationServerMetadata.issuer,
        aud: 'my-client-id',
        exp: Math.floor(Date.now() / 1000) + 3600,
        iat: Math.floor(Date.now() / 1000),
        sub: 'user-123',
      },
      signer: kidSigner,
      signJwsCallback: getSignJwsCallback([{ ...signerJwk, kid: 'key-1' }]),
    })

    const getJwksCalls: unknown[] = []
    await verifyIdTokenJwt({
      idToken: jwt,
      clientId: 'my-client-id',
      callbacks: {
        verifyJws: callbacks.verifyJws,
        getJwks: (jwksUri, options) => {
          getJwksCalls.push([jwksUri, options])
          return { keys: [{ ...signerJwkPublic, kid: 'key-1' }] }
        },
      },
      authorizationServer: authorizationServerMetadata,
    })

    expect(getJwksCalls).toEqual([[authorizationServerMetadata.jwks_uri, { kid: 'key-1' }]])
  })
})
