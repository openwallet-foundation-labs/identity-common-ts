import { base64url, stringToBytes } from '@owf/identity-common'
import { describe, expect, it } from 'vitest'
import type { VerifyJwsCallback, VerifyJwsCallbackContext } from '../callbacks'
import { JoseSignatureVerificationError } from '../error'
import { parseJws } from '../jws/parse-jws'
import { signCompactJws } from '../jws/sign-jws'
import { verifyJwsSignature } from '../jws/verify-jws'
import { verifyJwt } from '../jwt/verify-jwt'
import { createEs256Context, unsignedCompactJws } from './context'

const encode = (value: unknown) => base64url.encode(stringToBytes(JSON.stringify(value)))

describe('a verification callback that reports success without the key it verified with', () => {
  const jws = () => parseJws({ jws: unsignedCompactJws({ alg: 'ES256' }, { iss: 'https://issuer.example' }) })
  const expectedError = new JoseSignatureVerificationError(
    'Error during verification of the JWS. The verification callback reported the signature as verified, but did not return the jwk it was verified with.'
  )

  it('fails verification when signerJwk is missing', async () => {
    const verifyJwsCallback = (() => ({ verified: true })) as unknown as VerifyJwsCallback

    await expect(verifyJwsSignature({ jws: jws(), verifyJwsCallback })).rejects.toThrow(expectedError)
  })

  it('fails verification when signerJwk has no kty', async () => {
    const verifyJwsCallback = (() => ({ verified: true, signerJwk: { crv: 'P-256' } })) as unknown as VerifyJwsCallback

    await expect(verifyJwsSignature({ jws: jws(), verifyJwsCallback })).rejects.toThrow(expectedError)
  })

  it('fails verification when signerJwk is not an object', async () => {
    const verifyJwsCallback = (() => ({
      verified: true,
      signerJwk: 'did:example:123#key-1',
    })) as unknown as VerifyJwsCallback

    await expect(verifyJwsSignature({ jws: jws(), verifyJwsCallback })).rejects.toThrow(expectedError)
  })

  it('fails JWT verification when signerJwk is missing', async () => {
    const verifyJwsCallback = (() => ({ verified: true })) as unknown as VerifyJwsCallback
    const jwt = unsignedCompactJws({ alg: 'ES256' }, { iss: 'https://issuer.example' })

    await expect(verifyJwt({ jwt, verifyJwsCallback })).rejects.toThrow(JoseSignatureVerificationError)
  })
})

describe('a verification callback that throws', () => {
  it('fails verification with what the callback threw as the cause', async () => {
    const cause = new Error('the key could not be resolved')
    const jws = parseJws({ jws: unsignedCompactJws({ alg: 'ES256' }, {}) })

    await expect(
      verifyJwsSignature({
        jws,
        verifyJwsCallback: () => {
          throw cause
        },
      })
    ).rejects.toThrow(expect.objectContaining({ name: JoseSignatureVerificationError.name, cause }))
  })
})

/**
 * `compact` is given so that a callback that verifies a compact JWS as a whole keeps working, which
 * is only true when the compact serialization contains what was signed.
 */
describe('the compact serialization given to the verification callback', () => {
  const captureContext = () => {
    const contexts: VerifyJwsCallbackContext[] = []
    const verifyJwsCallback: VerifyJwsCallback = (_signer, context) => {
      contexts.push(context)
      return { verified: true, signerJwk: { kty: 'EC', crv: 'P-256', x: 'x', y: 'y' } }
    }
    return { contexts, verifyJwsCallback }
  }

  it('is the JWS itself when it carries its payload', async () => {
    const compact = unsignedCompactJws({ alg: 'ES256' }, { iss: 'https://issuer.example' })
    const { contexts, verifyJwsCallback } = captureContext()

    await verifyJwsSignature({ jws: parseJws({ jws: compact }), verifyJwsCallback })

    expect(contexts[0].compact).toBe(compact)
  })

  it('is not given for a JWS with a detached payload', async () => {
    const { contexts, verifyJwsCallback } = captureContext()
    const jws = parseJws({ jws: `${encode({ alg: 'ES256' })}..c2ln`, detachedPayload: 'transfer 1000' })

    await verifyJwsSignature({ jws, verifyJwsCallback })

    expect(contexts[0].compact).toBeUndefined()
  })

  it('is not returned by parseJws for a JWS with a detached payload', () => {
    const jws = parseJws({ jws: `${encode({ alg: 'ES256' })}..c2ln`, detachedPayload: 'transfer 1000' })

    expect(jws.compact).toBeUndefined()
  })

  it('does not let a signature over an empty payload verify a detached payload', async () => {
    const { signJws, verifyJws, publicJwk } = await createEs256Context()

    // Signed over `header.` — an empty payload — which is what the compact form of a detached JWS
    // looks like too
    const { compact } = await signCompactJws({
      protectedHeader: { alg: 'ES256' },
      payload: '',
      signer: { method: 'jwk', alg: 'ES256', publicJwk },
      signJwsCallback: signJws,
    })

    // A callback that verifies the compact serialization as a whole whenever it is given one
    const verifyCompactWhenGiven: VerifyJwsCallback = (signer, context) => {
      if (!context.compact) return verifyJws(signer, context)
      const [header, payload, signature] = context.compact.split('.')
      const signingInput = `${header}.${payload}`
      return verifyJws(signer, { ...context, signingInput, signingInputBytes: stringToBytes(signingInput), signature })
    }

    const jws = parseJws({ jws: compact, detachedPayload: 'transfer 1000 to mallory' })

    await expect(verifyJwsSignature({ jws, verifyJwsCallback: verifyCompactWhenGiven })).rejects.toThrow(
      JoseSignatureVerificationError
    )
  })
})
