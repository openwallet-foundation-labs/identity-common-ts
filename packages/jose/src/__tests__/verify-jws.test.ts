import { describe, expect, it } from 'vitest'
import { JoseAlgorithmNotAllowedError } from '../error'
import { parseJws } from '../jws/parse-jws'
import { signCompactJws } from '../jws/sign-jws'
import { verifyJwsSignature } from '../jws/verify-jws'
import { createEs256Context } from './context'

describe('verifyJwsSignature with a given signer', () => {
  // The callback verifies with `signer.alg`, which must be the alg the algorithm policy was applied to
  it('rejects a signer with another alg than the JWS', async () => {
    const { signJws, verifyJws, publicJwk } = await createEs256Context()
    const { compact } = await signCompactJws({
      protectedHeader: { alg: 'ES256' },
      payload: 'hello',
      signer: { method: 'jwk', alg: 'ES256', publicJwk },
      signJwsCallback: signJws,
    })
    let callbackCalled = false

    await expect(
      verifyJwsSignature({
        jws: parseJws({ jws: compact }),
        signer: { method: 'jwk', alg: 'ES384', publicJwk },
        verifyJwsCallback: (signer, context) => {
          callbackCalled = true
          return verifyJws(signer, context)
        },
      })
    ).rejects.toThrow(JoseAlgorithmNotAllowedError)
    expect(callbackCalled).toBe(false)
  })

  it('verifies against a signer with the alg of the JWS', async () => {
    const { signJws, verifyJws, publicJwk } = await createEs256Context()
    const signer = { method: 'jwk', alg: 'ES256', publicJwk } as const
    const { compact } = await signCompactJws({
      protectedHeader: { alg: 'ES256' },
      payload: 'hello',
      signer,
      signJwsCallback: signJws,
    })

    const result = await verifyJwsSignature({ jws: parseJws({ jws: compact }), signer, verifyJwsCallback: verifyJws })

    expect(result.signer).toEqual({ ...signer, publicJwk })
  })
})
