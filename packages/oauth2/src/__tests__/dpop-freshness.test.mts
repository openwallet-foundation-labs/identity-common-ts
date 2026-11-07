import type { Jwk } from '@owf/jose'
import * as jose from 'jose'
import { describe, expect, test } from 'vitest'
import { verifyAuthorizationRequest } from '../authorization-request/verify-authorization-request'
import { createDpopJwt, verifyDpopJwt } from '../dpop/dpop'
import { callbacks, getSignJwsCallback } from './util.mjs'

const request = { method: 'POST' as const, url: 'https://server.com/par', headers: new Headers() }

const createProof = async (options: { issuedAt?: Date; nonce?: string }) => {
  const { publicKey, privateKey } = await jose.generateKeyPair('ES256', { extractable: true })
  return createDpopJwt({
    callbacks: { ...callbacks, signJws: getSignJwsCallback([(await jose.exportJWK(privateKey)) as Jwk]) },
    request,
    signer: { method: 'jwk', alg: 'ES256', publicJwk: (await jose.exportJWK(publicKey)) as Jwk },
    ...options,
  })
}

describe('DPoP proof freshness', () => {
  // RFC 9449 Section 11.1: a server accepts a proof only for a limited time, or a leaked proof is valid forever
  test('rejects a proof created more than 300 seconds ago by default', async () => {
    const dpopJwt = await createProof({ issuedAt: new Date(Date.now() - 400_000) })

    await expect(verifyDpopJwt({ dpopJwt, request, callbacks })).rejects.toThrow(/more than 300 seconds in the past/)
    await expect(verifyDpopJwt({ dpopJwt, request, callbacks, maxProofAgeSeconds: 600 })).resolves.toBeDefined()
  })

  // RFC 9449 Section 8: the server can require a nonce it provided, for every request with a proof
  test('checks the nonce of the proof of an authorization request', async () => {
    const verify = async (nonce: string) =>
      verifyAuthorizationRequest({
        authorizationServerMetadata: { issuer: 'https://server.com', token_endpoint: 'https://server.com/token' },
        authorizationRequest: { client_id: 'wallet' },
        request,
        dpop: { jwt: await createProof({ nonce }), expectedNonce: 'server-nonce' },
        callbacks,
      })

    await expect(verify('stale-nonce')).rejects.toThrow()
    await expect(verify('server-nonce')).resolves.toBeDefined()
  })
})
