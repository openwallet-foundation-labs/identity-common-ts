import { calculateJwkThumbprint, decodeJwt, type Jwk, signJwt } from '@owf/jose'
import * as jose from 'jose'
import { beforeAll, describe, expect, test } from 'vitest'
import {
  createClientAttestationJwt,
  verifyClientAttestation,
  verifyClientAttestationJwt,
} from '../../client-attestation/client-attestation'
import {
  createClientAttestationPopJwt,
  verifyClientAttestationPopJwt,
} from '../../client-attestation/client-attestation-pop'
import {
  zClientAttestationJwtHeader,
  zClientAttestationJwtPayload,
  zClientAttestationPopJwtHeader,
  zClientAttestationPopJwtPayload,
} from '../../client-attestation/z-client-attestation'
import { Oauth2Error } from '../../error/Oauth2Error'
import {
  callbacks,
  didJwk,
  getSignJwsCallback,
  signerWithOwnKey,
  testAttester,
  verifyJwsTrustingDids,
} from '../util.mjs'

const authorizationServer = 'https://oauth2-auth-server.com'

async function generateEs256Key() {
  const { publicKey, privateKey } = await jose.generateKeyPair('ES256', { extractable: true })
  return {
    privateJwk: (await jose.exportJWK(privateKey)) as Jwk,
    publicJwk: (await jose.exportJWK(publicKey)) as Jwk,
  }
}

describe('Client (Wallet) Attestation', () => {
  // Attester signs the client attestation; the client instance holds the `cnf` key and signs the PoP.
  let instance: Awaited<ReturnType<typeof generateEs256Key>>
  let signJws: ReturnType<typeof getSignJwsCallback>
  let clientAttestationJwt: string
  let clientAttestation: ReturnType<
    typeof decodeJwt<typeof zClientAttestationJwtHeader, typeof zClientAttestationJwtPayload>
  >

  beforeAll(async () => {
    instance = await generateEs256Key()
    signJws = getSignJwsCallback([instance.privateJwk])

    clientAttestationJwt = await createClientAttestationJwt({
      callbacks: { signJws },
      clientId: 'wallet',
      confirmation: { jwk: instance.publicJwk },
      expiresAt: new Date(Date.now() + 3600 * 1000),
      signer: testAttester.signer,
    })

    clientAttestation = decodeJwt({
      jwt: clientAttestationJwt,
      headerSchema: zClientAttestationJwtHeader,
      payloadSchema: zClientAttestationJwtPayload,
    })
  })

  test('creates a draft-09 Client Attestation JWT without an `iss` claim', () => {
    expect(clientAttestation.payload.iss).toBeUndefined()
    expect(clientAttestation.payload.sub).toBe('wallet')
    expect(clientAttestation.payload.cnf.jwk).toEqual(instance.publicJwk)
  })

  test('creates a draft-09 PoP JWT (no `iss`, no `exp`, uses `challenge`) that verifies', async () => {
    const clientAttestationPopJwt = await createClientAttestationPopJwt({
      callbacks: { signJws, generateRandom: callbacks.generateRandom },
      authorizationServer,
      clientAttestation: clientAttestationJwt,
      challenge: 'challenge-123',
    })

    const { payload } = decodeJwt({
      jwt: clientAttestationPopJwt,
      headerSchema: zClientAttestationPopJwtHeader,
      payloadSchema: zClientAttestationPopJwtPayload,
    })
    expect(payload.iss).toBeUndefined()
    expect(payload.exp).toBeUndefined()
    expect(payload.nonce).toBeUndefined()
    expect(payload.challenge).toBe('challenge-123')
    expect(payload.aud).toBe(authorizationServer)
    expect(payload.jti).toEqual(expect.any(String))

    await expect(
      verifyClientAttestationPopJwt({
        callbacks: { verifyJws: callbacks.verifyJws },
        authorizationServer,
        clientAttestation,
        clientAttestationPopJwt,
        expectedChallenge: 'challenge-123',
      })
    ).resolves.toBeDefined()
  })

  // A PoP is created for each request, so an old one, or one without `iat` (draft 09 §5.2), is a replayed one
  test('rejects a PoP JWT created more than 300 seconds ago', async () => {
    const clientAttestationPopJwt = await createClientAttestationPopJwt({
      callbacks: { signJws, generateRandom: callbacks.generateRandom },
      authorizationServer,
      clientAttestation: clientAttestationJwt,
      issuedAt: new Date(Date.now() - 400_000),
    })

    await expect(
      verifyClientAttestationPopJwt({
        callbacks: { verifyJws: callbacks.verifyJws },
        authorizationServer,
        clientAttestation,
        clientAttestationPopJwt,
      })
    ).rejects.toThrow(/more than 300 seconds in the past/)
  })

  test('rejects a PoP JWT without iat', async () => {
    const { jwt: clientAttestationPopJwt } = await signJwt({
      signer: { method: 'jwk', alg: 'ES256', publicJwk: instance.publicJwk },
      signJwsCallback: signJws,
      header: { typ: 'oauth-client-attestation-pop+jwt', alg: 'ES256' },
      payload: { aud: authorizationServer, jti: 'jti-1' },
    })

    await expect(
      verifyClientAttestationPopJwt({
        callbacks: { verifyJws: callbacks.verifyJws },
        authorizationServer,
        clientAttestation,
        clientAttestationPopJwt,
      })
    ).rejects.toThrow('iat')
  })

  // draft 09 §6: the server enforces the challenge it issued, which verifyClientAttestation could not
  test('verifyClientAttestation rejects a PoP JWT with another challenge than the expected one', async () => {
    const clientAttestationPopJwt = await createClientAttestationPopJwt({
      callbacks: { signJws, generateRandom: callbacks.generateRandom },
      authorizationServer,
      clientAttestation: clientAttestationJwt,
      challenge: 'stale-challenge',
    })
    const verify = (expectedChallenge: string) =>
      verifyClientAttestation({
        callbacks,
        authorizationServer,
        clientAttestationJwt,
        clientAttestationPopJwt,
        expectedChallenge,
      })

    await expect(verify('issued-challenge')).rejects.toThrow("'challenge' does not match expected value")
    await expect(verify('stale-challenge')).resolves.toBeDefined()
  })

  test('verifies a legacy (<= draft 07) PoP JWT carrying `iss` and `nonce`', async () => {
    const now = Math.floor(Date.now() / 1000)
    const { jwt: legacyPopJwt } = await signJwt({
      signer: { method: 'jwk', alg: 'ES256', publicJwk: instance.publicJwk },
      signJwsCallback: signJws,
      header: { typ: 'oauth-client-attestation-pop+jwt', alg: 'ES256' },
      payload: {
        iss: 'wallet',
        aud: authorizationServer,
        iat: now,
        exp: now + 300,
        jti: 'legacy-jti',
        nonce: 'legacy-nonce',
      },
    })

    await expect(
      verifyClientAttestationPopJwt({
        callbacks: { verifyJws: callbacks.verifyJws },
        authorizationServer,
        clientAttestation,
        clientAttestationPopJwt: legacyPopJwt,
        // `expectedNonce` is the deprecated alias for `expectedChallenge`
        expectedNonce: 'legacy-nonce',
      })
    ).resolves.toBeDefined()
  })

  test('rejects a legacy PoP JWT whose `iss` does not match the attestation `sub`', async () => {
    const now = Math.floor(Date.now() / 1000)
    const { jwt: legacyPopJwt } = await signJwt({
      signer: { method: 'jwk', alg: 'ES256', publicJwk: instance.publicJwk },
      signJwsCallback: signJws,
      header: { typ: 'oauth-client-attestation-pop+jwt', alg: 'ES256' },
      payload: {
        iss: 'not-wallet',
        aud: authorizationServer,
        iat: now,
        jti: 'legacy-jti',
      },
    })

    await expect(
      verifyClientAttestationPopJwt({
        callbacks: { verifyJws: callbacks.verifyJws },
        authorizationServer,
        clientAttestation,
        clientAttestationPopJwt: legacyPopJwt,
      })
    ).rejects.toThrow("'iss'")
  })

  describe('verifyClientAttestationPopJwt', () => {
    // A PoP JWT as `createClientAttestationPopJwt` creates it, but with the given typ
    const signClientAttestationPopJwt = async (typ: string) => {
      const { jwt } = await signJwt({
        signer: { method: 'jwk', alg: 'ES256', publicJwk: instance.publicJwk },
        signJwsCallback: signJws,
        header: { typ, alg: 'ES256' },
        payload: { aud: authorizationServer, iat: Math.floor(Date.now() / 1000), jti: 'pop-jti' },
      })

      return jwt
    }

    test.each(['application/oauth-client-attestation-pop+jwt', 'OAuth-Client-Attestation-PoP+JWT'])(
      'verifies a PoP JWT whose typ is %s',
      async (typ) => {
        const { header } = await verifyClientAttestationPopJwt({
          callbacks: { verifyJws: callbacks.verifyJws },
          authorizationServer,
          clientAttestation,
          clientAttestationPopJwt: await signClientAttestationPopJwt(typ),
        })

        expect(header.typ).toEqual(typ)
      }
    )

    test('rejects a PoP JWT with the typ of a client attestation', async () => {
      await expect(
        verifyClientAttestationPopJwt({
          callbacks: { verifyJws: callbacks.verifyJws },
          authorizationServer,
          clientAttestation,
          clientAttestationPopJwt: await signClientAttestationPopJwt('oauth-client-attestation+jwt'),
        })
      ).rejects.toThrow(`typ: typ must be oauth-client-attestation-pop+jwt (invalid_typ)`)
    })
  })

  describe('verifyClientAttestationJwt', () => {
    // A client attestation as `createClientAttestationJwt` creates it, but with the given typ
    const signClientAttestationJwt = async (typ: string) => {
      const now = Math.floor(Date.now() / 1000)
      const { jwt } = await signJwt({
        signer: testAttester.signer,
        signJwsCallback: signJws,
        header: { typ, alg: 'ES256', kid: testAttester.signer.kid },
        payload: { sub: 'wallet', iat: now, exp: now + 300, cnf: { jwk: instance.publicJwk } },
      })

      return jwt
    }

    test.each(['application/oauth-client-attestation+jwt', 'OAuth-Client-Attestation+JWT'])(
      'verifies a client attestation whose typ is %s',
      async (typ) => {
        const { header } = await verifyClientAttestationJwt({
          callbacks,
          clientAttestationJwt: await signClientAttestationJwt(typ),
        })

        expect(header.typ).toEqual(typ)
      }
    )

    // The authorization server must trust the attester (draft-ietf-oauth-attestation-based-client-auth), but
    // `verifyJws` accepts a key from a `jwk` header for DPoP and PoP JWTs, so a client could attest itself with it
    test('rejects a client attestation signed with a jwk signer', async () => {
      const clientAttestationJwt = await createClientAttestationJwt({
        callbacks: { signJws },
        clientId: 'wallet',
        confirmation: { jwk: instance.publicJwk },
        expiresAt: new Date(Date.now() + 3600 * 1000),
        signer: signerWithOwnKey('jwk', instance.publicJwk),
      })

      await expect(verifyClientAttestationJwt({ callbacks, clientAttestationJwt })).rejects.toThrow('method jwk')
    })

    // A DID signer is passed to `verifyJws`, which must check that the DID belongs to a trusted attester
    test('verifies a client attestation signed with a did signer only if verifyJws trusts the did', async () => {
      const attester = await generateEs256Key()
      const clientAttestationJwt = await createClientAttestationJwt({
        callbacks: { signJws: getSignJwsCallback([attester.privateJwk]) },
        clientId: 'wallet',
        confirmation: { jwk: instance.publicJwk },
        expiresAt: new Date(Date.now() + 3600 * 1000),
        signer: signerWithOwnKey('did', attester.publicJwk),
      })

      const { signer } = await verifyClientAttestationJwt({
        callbacks: { ...callbacks, verifyJws: verifyJwsTrustingDids([didJwk(attester.publicJwk)]) },
        clientAttestationJwt,
      })
      expect(signer).toMatchObject({ method: 'did', didUrl: `${didJwk(attester.publicJwk)}#0` })

      await expect(
        verifyClientAttestationJwt({
          callbacks: { ...callbacks, verifyJws: verifyJwsTrustingDids([didJwk(instance.publicJwk)]) },
          clientAttestationJwt,
        })
      ).rejects.toThrow('client attestation jwt verification failed.')
    })

    test('rejects a client attestation with the typ of a client attestation PoP', async () => {
      await expect(
        verifyClientAttestationJwt({
          callbacks,
          clientAttestationJwt: await signClientAttestationJwt('oauth-client-attestation-pop+jwt'),
        })
      ).rejects.toThrow(`typ: typ must be oauth-client-attestation+jwt (invalid_typ)`)
    })

    test('returns the jwk thumbprint of the cnf key', async () => {
      const { confirmationJwkThumbprint } = await verifyClientAttestationJwt({ callbacks, clientAttestationJwt })

      expect(confirmationJwkThumbprint).toEqual(
        await calculateJwkThumbprint({
          hashAlgorithm: 'sha-256',
          hashCallback: callbacks.hash,
          jwk: instance.publicJwk,
        })
      )
    })

    test('accepts the expected jwk thumbprint of the cnf key', async () => {
      const { confirmationJwkThumbprint } = await verifyClientAttestationJwt({ callbacks, clientAttestationJwt })

      await expect(
        verifyClientAttestationJwt({
          callbacks,
          clientAttestationJwt,
          expectedConfirmationJwkThumbprint: confirmationJwkThumbprint,
        })
      ).resolves.toMatchObject({ confirmationJwkThumbprint })
    })

    test('rejects another expected jwk thumbprint than of the cnf key, without exposing the expected value', async () => {
      const { confirmationJwkThumbprint } = await verifyClientAttestationJwt({ callbacks, clientAttestationJwt })

      await expect(
        verifyClientAttestationJwt({
          callbacks,
          clientAttestationJwt,
          expectedConfirmationJwkThumbprint: 'other-thumbprint',
        })
      ).rejects.toThrow(
        new Oauth2Error(
          `Client attestation 'cnf' jwk thumbprint '${confirmationJwkThumbprint}' does not match the expected jwk thumbprint. Use the same client instance key for all requests.`
        )
      )
    })

    test('rejects another expected client id than the sub, without exposing the expected value', async () => {
      await expect(
        verifyClientAttestationJwt({ callbacks, clientAttestationJwt, expectedClientId: 'wallet' })
      ).resolves.toBeDefined()

      await expect(
        verifyClientAttestationJwt({ callbacks, clientAttestationJwt, expectedClientId: 'other-wallet' })
      ).rejects.toThrow(
        new Oauth2Error("Client attestation 'sub' (client_id) value 'wallet' does not match the expected client id.")
      )
    })
  })

  describe('verifyClientAttestation', () => {
    const invalidClient = { status: 401, errorResponse: { error: 'invalid_client' } }

    test('reports a client attestation that fails schema validation as invalid_client', async () => {
      const now = Math.floor(Date.now() / 1000)
      const { jwt: clientAttestationWithoutSub } = await signJwt({
        signer: testAttester.signer,
        signJwsCallback: signJws,
        header: { typ: 'oauth-client-attestation+jwt', alg: 'ES256' },
        payload: { iat: now, exp: now + 300, cnf: { jwk: instance.publicJwk } },
      })
      const clientAttestationPopJwt = await createClientAttestationPopJwt({
        callbacks: { signJws, generateRandom: callbacks.generateRandom },
        authorizationServer,
        clientAttestation: clientAttestationJwt,
      })

      await expect(
        verifyClientAttestation({
          callbacks: { verifyJws: callbacks.verifyJws, hash: callbacks.hash },
          authorizationServer,
          clientAttestationJwt: clientAttestationWithoutSub,
          clientAttestationPopJwt,
        })
      ).rejects.toMatchObject(invalidClient)
    })

    test('reports a client attestation PoP that fails schema validation as invalid_client', async () => {
      const { jwt: clientAttestationPopWithoutJti } = await signJwt({
        signer: { method: 'jwk', alg: 'ES256', publicJwk: instance.publicJwk },
        signJwsCallback: signJws,
        header: { typ: 'oauth-client-attestation-pop+jwt', alg: 'ES256' },
        payload: { aud: authorizationServer, iat: Math.floor(Date.now() / 1000) },
      })

      await expect(
        verifyClientAttestation({
          callbacks: { verifyJws: callbacks.verifyJws, hash: callbacks.hash },
          authorizationServer,
          clientAttestationJwt,
          clientAttestationPopJwt: clientAttestationPopWithoutJti,
        })
      ).rejects.toMatchObject(invalidClient)
    })
  })
})
