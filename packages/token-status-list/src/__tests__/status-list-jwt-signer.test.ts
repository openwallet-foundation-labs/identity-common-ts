import { hmac } from '@noble/hashes/hmac.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { base64url, stringToBytes } from '@owf/identity-common'
import {
  JoseAlgorithmNotAllowedError,
  JoseSignatureVerificationError,
  JoseSignerError,
  type SignJwsCallback,
  type VerifyJwsCallback,
} from '@owf/jose'
import { describe, expect, it } from 'vitest'
import { signStatusListJwt, type VerifyStatusListJwtOptions, verifyStatusListJwt } from '../status-list-jwt'
import { jwsPublicJwk, verifyJws } from './context'
import {
  now,
  secondsFromNow,
  signStatusListToken,
  statusListWith,
  uri,
  withInvalidSignature,
} from './status-list-jwt-tokens'

// How `verifyStatusListJwt` establishes the signer and applies the algorithm policy of `@owf/jose`

const verify = (jwt: string, options: Partial<Omit<VerifyStatusListJwtOptions, 'jwt'>> = {}) =>
  verifyStatusListJwt({ jwt, uri, now, verifyJwsCallback: verifyJws, ...options })

const didKid = 'did:example:123#key-1'

describe('the signer', () => {
  it('is a custom signer when the header does not identify the key', async () => {
    const { signer } = await verify(await signStatusListToken({}, { kid: 'status-key' }))

    expect(signer).toEqual({ method: 'custom', alg: 'ES256', kid: 'status-key', publicJwk: jwsPublicJwk })
  })

  it('is the jwk in the header', async () => {
    const { signer } = await verify(await signStatusListToken({}, { jwk: jwsPublicJwk }))

    expect(signer).toEqual({ method: 'jwk', alg: 'ES256', publicJwk: jwsPublicJwk })
  })

  // A verifier that only trusts certificates must be able to refuse a key the token brings along
  it('rejects a jwk in the header when only x5c signers are allowed', async () => {
    const verification = verify(await signStatusListToken({}, { jwk: jwsPublicJwk }), {
      allowedSignerMethods: ['x5c'],
    })

    await expect(verification).rejects.toThrow(JoseSignerError)
    await expect(verification).rejects.toThrow('signer method(s) that are not allowed')
  })

  it('is the signer it is given rather than the one in the header', async () => {
    const { signer } = await verify(await signStatusListToken({}, { jwk: jwsPublicJwk }), {
      signer: { method: 'custom', alg: 'ES256', kid: 'configured-key' },
    })

    expect(signer).toEqual({ method: 'custom', alg: 'ES256', kid: 'configured-key', publicJwk: jwsPublicJwk })
  })

  it('rejects a did kid that is not the did of iss', async () => {
    const verification = verify(await signStatusListToken({ iss: 'https://example.com' }, { kid: didKid }))

    await expect(verification).rejects.toThrow(JoseSignerError)
    await expect(verification).rejects.toThrow("different from the did value in 'iss'")
  })

  it('is a did kid that is not the did of iss when allowDidKidIssuerMismatch is set', async () => {
    const jwt = await signStatusListToken({ iss: 'https://example.com' }, { kid: didKid })

    const { signer } = await verify(jwt, { allowDidKidIssuerMismatch: true })

    expect(signer).toEqual({ method: 'did', alg: 'ES256', didUrl: didKid, publicJwk: jwsPublicJwk })
  })

  it('rejects a header that identifies the signer in two ways', async () => {
    const verification = verify(
      await signStatusListToken({ iss: 'did:example:123' }, { kid: didKid, jwk: jwsPublicJwk })
    )

    await expect(verification).rejects.toThrow(JoseSignerError)
    await expect(verification).rejects.toThrow("identifies the signer in 2 ways ('did', 'jwk')")
  })

  it('is the first signer the header identifies when allowMultipleSignerMethods is set', async () => {
    const jwt = await signStatusListToken({ iss: 'did:example:123' }, { kid: didKid, jwk: jwsPublicJwk })

    const { signer } = await verify(jwt, { allowMultipleSignerMethods: true })

    expect(signer.method).toBe('did')
  })
})

describe('the algorithm', () => {
  it('rejects an algorithm that is not allowed', async () => {
    const verification = verify(await signStatusListToken(), { allowedAlgorithms: ['ES384'] })

    await expect(verification).rejects.toThrow(JoseAlgorithmNotAllowedError)
    await expect(verification).rejects.toThrow("uses alg 'ES256', but the allowed algorithms are 'ES384'")
  })

  it('accepts an algorithm that is allowed', async () => {
    const { header } = await verify(await signStatusListToken(), { allowedAlgorithms: ['ES256'] })

    expect(header.alg).toBe('ES256')
  })

  describe('of a token with a MAC', () => {
    const macKey = stringToBytes('a secret of at least thirty-two bytes')
    const macJwk = { kty: 'oct', k: base64url.encode(macKey) }
    const mac = (input: Uint8Array) => base64url.encode(hmac(sha256, macKey, input))

    const signMac: SignJwsCallback = (_signer, { signingInputBytes }) => ({
      signature: mac(signingInputBytes),
      signerJwk: macJwk,
    })
    const verifyMac: VerifyJwsCallback = (_signer, { signingInputBytes, signature }) =>
      mac(signingInputBytes) === signature ? { verified: true, signerJwk: macJwk } : { verified: false }

    const macToken = async () =>
      (
        await signStatusListJwt({
          statusList: statusListWith(),
          payload: { sub: uri, iat: secondsFromNow(-60) },
          signer: { method: 'custom', alg: 'HS256' },
          signJwsCallback: signMac,
        })
      ).jwt

    it('rejects a symmetric algorithm', async () => {
      const verification = verify(await macToken(), { verifyJwsCallback: verifyMac })

      await expect(verification).rejects.toThrow(JoseAlgorithmNotAllowedError)
      await expect(verification).rejects.toThrow("uses the symmetric algorithm 'HS256'")
    })

    it('accepts a symmetric algorithm when allowSymmetricAlgorithms is set', async () => {
      const { signer } = await verify(await macToken(), {
        verifyJwsCallback: verifyMac,
        allowSymmetricAlgorithms: true,
      })

      expect(signer).toEqual({ method: 'custom', alg: 'HS256', publicJwk: macJwk })
    })
  })
})

describe('a signature that does not verify', () => {
  it('is reported as a failure to verify the Status List Token', async () => {
    const verification = verify(await withInvalidSignature(await signStatusListToken()))

    await expect(verification).rejects.toThrow(JoseSignatureVerificationError)
    await expect(verification).rejects.toThrow('Error during verification of the Status List Token.')
  })

  it('is reported with the errorMessage it is given', async () => {
    const verification = verify(await withInvalidSignature(await signStatusListToken()), {
      errorMessage: 'Status list rejected.',
    })

    await expect(verification).rejects.toThrow(JoseSignatureVerificationError)
    await expect(verification).rejects.toThrow('Status list rejected.')
  })
})
