import { addSecondsToDate } from '@openid4vc/utils'
import { describe, expect, test } from 'vitest'
import { callbacks, getSignJwsCallback } from '../../../../../../oauth2/src/__tests__/util.mjs'
import {
  createCredentialRequestJwtProof,
  verifyCredentialRequestJwtProof,
} from '../../../../formats/proof-type/jwt/jwt-proof-type'

const proofJwk = {
  kty: 'EC',
  d: 'ihMFBAANWoQDlKa-heCamTFADIUUS3H9vv7ednax498',
  crv: 'P-256',
  x: 'So52pS_IAc-AyzdX8LMBMxx9Zm2sPPOTMvXDrvZF53I',
  y: 'LZ2D24wpGdrM4Ex71SU9uFobvHTLmwXza4uhFp9Bpg8',
}
const { d: _, ...proofJwkPublic } = proofJwk

const credentialIssuer = 'https://credential-issuer.com'

describe('verifyCredentialRequestJwtProof', () => {
  describe('allowedSkewInSeconds', () => {
    const now = new Date('2026-01-01T00:00:00Z')

    const jwt = createCredentialRequestJwtProof({
      callbacks: { ...callbacks, signJws: getSignJwsCallback([proofJwk]) },
      credentialIssuer,
      nonce: 'some-nonce',
      issuedAt: addSecondsToDate(now, 10),
      signer: { method: 'jwk', alg: 'ES256', publicJwk: proofJwkPublic },
    })

    const verify = async (allowedSkewInSeconds?: number) =>
      verifyCredentialRequestJwtProof({
        callbacks,
        credentialIssuer,
        expectedNonce: 'some-nonce',
        jwt: await jwt,
        now,
        allowedSkewInSeconds,
      })

    test('accepts a proof whose iat is 10 seconds in the future with the default skew', async () => {
      await expect(verify()).resolves.toBeDefined()
    })

    test('rejects a proof whose iat is 10 seconds in the future with an allowed skew of 0', async () => {
      await expect(verify(0)).rejects.toThrow(/iat: .* \(not_yet_valid\)/)
    })
  })
})
