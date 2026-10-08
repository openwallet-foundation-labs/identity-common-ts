import * as jose from 'jose'
import { describe, expect, test } from 'vitest'
import { verifyAuthorizationRequest } from '../../authorization-request/verify-authorization-request'
import { createClientAttestationJwt } from '../../client-attestation/client-attestation'
import { createClientAttestationPopJwt } from '../../client-attestation/client-attestation-pop'
import type { Jwk } from '../../common/jwk/z-jwk'
import { Oauth2ErrorCodes } from '../../common/z-oauth2-error'
import type { AuthorizationServerMetadata } from '../../metadata/authorization-server/z-authorization-server-metadata'
import { callbacks, getSignJwtCallback } from '../util.mjs'

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
  const attester = await generateEs256Key()
  const signJwt = getSignJwtCallback([attester.privateJwk, instance.privateJwk])
  const clientAttestationJwt = await createClientAttestationJwt({
    callbacks: { signJwt },
    clientId: 'wallet',
    confirmation: { jwk: instance.publicJwk },
    expiresAt: new Date(Date.now() + 3600 * 1000),
    signer: { method: 'jwk', alg: 'ES256', publicJwk: attester.publicJwk },
  })
  const clientAttestationPopJwt = await createClientAttestationPopJwt({
    callbacks: { signJwt, generateRandom: callbacks.generateRandom },
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
