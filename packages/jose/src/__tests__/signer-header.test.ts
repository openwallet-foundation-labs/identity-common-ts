import { describe, expect, it } from 'vitest'
import type { VerifyJwsCallback } from '../callbacks'
import { jwsHeaderFromSigner } from '../jws/signer'
import { signJwt } from '../jwt/sign-jwt'
import { verifyJwt } from '../jwt/verify-jwt'
import { certificateChain } from './certificates'
import { createEs256Context } from './context'

const publicJwk = { kty: 'EC', crv: 'P-256', x: 'x', y: 'y' }

describe('the header parameters that identify a signer', () => {
  // A custom signer is established out of band, so its key id is all a verifier has to find the key
  it('adds the kid of a custom signer', () => {
    expect(jwsHeaderFromSigner({ method: 'custom', alg: 'ES256', kid: 'key-2' })).toStrictEqual({
      alg: 'ES256',
      kid: 'key-2',
    })
  })

  it('adds no kid for a custom signer without one', () => {
    expect(jwsHeaderFromSigner({ method: 'custom', alg: 'ES256' })).toStrictEqual({ alg: 'ES256' })
  })

  it('does not add the kid of a jwk signer', () => {
    expect(jwsHeaderFromSigner({ method: 'jwk', alg: 'ES256', publicJwk, kid: 'key-2' })).toStrictEqual({
      alg: 'ES256',
      jwk: publicJwk,
    })
  })

  it('does not add the kid of an x5c signer', () => {
    expect(jwsHeaderFromSigner({ method: 'x5c', alg: 'ES256', x5c: certificateChain, kid: 'key-2' })).toStrictEqual({
      alg: 'ES256',
      x5c: certificateChain,
    })
  })

  it('adds the did url of a did signer as the kid', () => {
    expect(
      jwsHeaderFromSigner({ method: 'did', alg: 'ES256', didUrl: 'did:example:123#key-1', kid: 'other' })
    ).toStrictEqual({ alg: 'ES256', kid: 'did:example:123#key-1' })
  })

  it('adds the kid and the trust chain of a federation signer', () => {
    expect(
      jwsHeaderFromSigner({ method: 'federation', alg: 'ES256', kid: 'key-1', trustChain: ['ec1', 'ec2'] })
    ).toStrictEqual({ alg: 'ES256', kid: 'key-1', trust_chain: ['ec1', 'ec2'] })
  })

  it('gives the verification callback the kid of the custom signer that signed', async () => {
    const { signJws, verifyJws } = await createEs256Context()
    const signer = { method: 'custom', alg: 'ES256', kid: 'key-2' } as const

    const { jwt } = await signJwt({
      header: { ...jwsHeaderFromSigner(signer), typ: 'example+jwt' },
      payload: { iss: 'https://issuer.example' },
      signer,
      signJwsCallback: signJws,
    })

    const signers: unknown[] = []
    const capturingVerifyJws: VerifyJwsCallback = (verifiedSigner, context) => {
      signers.push(verifiedSigner)
      return verifyJws(verifiedSigner, context)
    }
    await verifyJwt({ jwt, verifyJwsCallback: capturingVerifyJws })

    expect(signers).toEqual([{ method: 'custom', alg: 'ES256', kid: 'key-2' }])
  })
})
