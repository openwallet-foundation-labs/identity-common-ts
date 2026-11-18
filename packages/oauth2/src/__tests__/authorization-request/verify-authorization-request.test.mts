import type { Jwk } from '@owf/jose'
import * as jose from 'jose'
import { describe, expect, test } from 'vitest'
import { verifyAuthorizationRequest } from '../../authorization-request/verify-authorization-request'
import { createClientAttestationJwt } from '../../client-attestation/client-attestation'
import { createClientAttestationPopJwt } from '../../client-attestation/client-attestation-pop'
import { Oauth2ErrorCodes } from '../../common/z-oauth2-error'
import type { AuthorizationServerMetadata } from '../../metadata/authorization-server/z-authorization-server-metadata'
import { callbacks, getSignJwsCallback, testAttester } from '../util.mjs'

const authorizationServerMetadata = {
  issuer: 'https://server.com',
  token_endpoint: 'https://server.com/token',
} satisfies AuthorizationServerMetadata

async function generateEs256Key() {
  const { publicKey, privateKey } = await jose.generateKeyPair('ES256', { extractable: true })
  return {
    privateJwk: (await jose.exportJWK(privateKey)) as Jwk,
    publicJwk: (await jose.exportJWK(publicKey)) as Jwk,
  }
}

async function createClientAttestation(instance: Awaited<ReturnType<typeof generateEs256Key>>) {
  const signJws = getSignJwsCallback([instance.privateJwk])
  const clientAttestationJwt = await createClientAttestationJwt({
    callbacks: { signJws },
    clientId: 'wallet',
    confirmation: { jwk: instance.publicJwk },
    expiresAt: new Date(Date.now() + 3600 * 1000),
    signer: testAttester.signer,
  })
  const clientAttestationPopJwt = await createClientAttestationPopJwt({
    callbacks: { signJws, generateRandom: callbacks.generateRandom },
    authorizationServer: authorizationServerMetadata.issuer,
    clientAttestation: clientAttestationJwt,
  })
  return { clientAttestationJwt, clientAttestationPopJwt }
}

const verify = (clientAttestation: Awaited<ReturnType<typeof createClientAttestation>>, expected?: string) =>
  verifyAuthorizationRequest({
    authorizationServerMetadata,
    authorizationRequest: { client_id: 'wallet' },
    request: { headers: new Headers(), method: 'POST', url: 'https://server.com/par' },
    clientAttestation: { ...clientAttestation, expectedConfirmationJwkThumbprint: expected },
    callbacks,
  })

describe('Verify client instance key of Authorization Request', () => {
  test('accepts the client instance key of an earlier request of the session', async () => {
    const instance = await generateEs256Key()
    const first = await verify(await createClientAttestation(instance))
    const thumbprint = first.clientAttestation?.clientAttestation.confirmationJwkThumbprint

    const second = await verify(await createClientAttestation(instance), thumbprint)
    expect(second.clientAttestation?.clientAttestation.confirmationJwkThumbprint).toEqual(thumbprint)
  })

  test('rejects another client instance key than in an earlier request of the session', async () => {
    const first = await verify(await createClientAttestation(await generateEs256Key()))

    await expect(
      verify(
        await createClientAttestation(await generateEs256Key()),
        first.clientAttestation?.clientAttestation.confirmationJwkThumbprint
      )
    ).rejects.toMatchObject({ errorResponse: { error: Oauth2ErrorCodes.InvalidClient } })
  })
})

// RFC 9700 §4.1.3: exact matching against the redirect URIs registered for the client
describe('Verify redirect_uri of Authorization Request', () => {
  const verifyRedirectUri = (redirectUri: string | undefined, allowedRedirectUris: string[]) =>
    verifyAuthorizationRequest({
      authorizationServerMetadata,
      authorizationRequest: { client_id: 'wallet', redirect_uri: redirectUri },
      allowedRedirectUris,
      request: { headers: new Headers(), method: 'POST', url: 'https://server.com/par' },
      callbacks,
    })

  test('accepts a registered redirect_uri', async () => {
    await expect(
      verifyRedirectUri('https://wallet.example/cb', ['https://other.example/cb', 'https://wallet.example/cb'])
    ).resolves.toBeDefined()
  })

  test('rejects a redirect_uri that is not registered', async () => {
    await expect(verifyRedirectUri('https://attacker.example/cb', ['https://wallet.example/cb'])).rejects.toMatchObject(
      { errorResponse: { error: Oauth2ErrorCodes.InvalidRequest } }
    )
    // No prefix matching or normalization
    await expect(verifyRedirectUri('https://wallet.example/cb/x', ['https://wallet.example/cb'])).rejects.toThrow(
      `The 'redirect_uri' is not registered for the client`
    )
    await expect(verifyRedirectUri('https://WALLET.example/cb', ['https://wallet.example/cb'])).rejects.toThrow(
      `The 'redirect_uri' is not registered for the client`
    )
    await expect(verifyRedirectUri('https://wallet.example/cb', [])).rejects.toThrow(
      `The 'redirect_uri' is not registered for the client`
    )
  })

  // RFC 6749 §3.1.2.3: the redirect_uri can only be left out if a single one is registered
  test('requires a redirect_uri unless a single one is registered', async () => {
    await expect(verifyRedirectUri(undefined, ['https://wallet.example/cb'])).resolves.toBeDefined()
    await expect(
      verifyRedirectUri(undefined, ['https://wallet.example/cb', 'https://other.example/cb'])
    ).rejects.toThrow(`Missing required 'redirect_uri' in authorization request`)
  })
})
