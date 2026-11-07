import { type Jwk, signJwt } from '@owf/jose'
import * as jose from 'jose'
import { describe, expect, test } from 'vitest'
import { callbacks, getSignJwsCallback, getVerifyJwsCallback } from '../../../../oauth2/src/__tests__/util.mjs'
import { verifyJarRequest } from '../../jar/handle-jar-request/verify-jar-request.js'

const now = new Date('2026-01-01T00:00:00.000Z')
const seconds = (date: Date) => Math.floor(date.getTime() / 1000)

// RFC 9101 Section 6.1: a request object can be signed and then encrypted
describe('verifyJarRequest with an encrypted request object', () => {
  test('decrypts the compact JWE and verifies the signed request object inside', async () => {
    const signing = await jose.generateKeyPair('ES256', { extractable: true })
    const encryption = await jose.generateKeyPair('ECDH-ES', { extractable: true })
    // The key of the pre-registered client, which the wallet knows out of band
    const signingJwk = { ...((await jose.exportJWK(signing.publicKey)) as Jwk), kid: 'verifier-key' }
    const encryptionJwk = { ...((await jose.exportJWK(encryption.publicKey)) as Jwk), kid: 'enc-key' }

    const { jwt: requestObject } = await signJwt({
      header: { typ: 'oauth-authz-req+jwt', kid: signingJwk.kid },
      payload: {
        client_id: 'verifier',
        response_type: 'vp_token',
        response_mode: 'direct_post',
        response_uri: 'https://verifier.example/response',
        nonce: 'nonce',
        exp: seconds(now) + 60,
      },
      signer: { method: 'custom', alg: 'ES256', kid: signingJwk.kid },
      signJwsCallback: getSignJwsCallback([
        { ...((await jose.exportJWK(signing.privateKey)) as Jwk), kid: signingJwk.kid },
      ]),
    })
    const request = await new jose.CompactEncrypt(new TextEncoder().encode(requestObject))
      .setProtectedHeader({ alg: 'ECDH-ES', enc: 'A256GCM', kid: 'enc-key' })
      .encrypt(encryption.publicKey)

    const result = await verifyJarRequest({
      jarRequestParams: { client_id: 'verifier', request },
      callbacks: {
        ...callbacks,
        verifyJws: getVerifyJwsCallback({ publicJwks: [signingJwk] }),
        decryptJwe: async (jwe) => {
          const { plaintext } = await jose.compactDecrypt(jwe, encryption.privateKey)
          return { decrypted: true, payload: new TextDecoder().decode(plaintext), decryptionJwk: encryptionJwk }
        },
      },
      now,
    })

    expect(result.decryptionJwk).toEqual(encryptionJwk)
    expect(result.authorizationRequestPayload).toMatchObject({ client_id: 'verifier', nonce: 'nonce' })
    expect(result.signer).toMatchObject({ method: 'custom', publicJwk: signingJwk })
  })
})
