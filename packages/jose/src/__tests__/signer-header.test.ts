import { describe, expect, it, vi } from 'vitest'
import type { SignJwsCallback, VerifyJwsCallback } from '../callbacks'
import { JoseInvalidArgumentError } from '../error'
import { type JwsSigner, jwsHeaderFromSigner } from '../jws/signer'
import { decodeJwt } from '../jwt/decode-jwt'
import { signJwt } from '../jwt/sign-jwt'
import { verifyJwt } from '../jwt/verify-jwt'
import { certificateChain, leafCertificate, rfc7517Certificate, rootCertificate } from './certificates'
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

const { signJws, publicJwk: jwsPublicJwk } = await createEs256Context()

const x5c = [leafCertificate, rootCertificate]
const otherCertificate = rfc7517Certificate
const didUrl = 'did:example:issuer#key-1'
const trustChain: [string, ...string[]] = ['entity-statement', 'trust-anchor-statement']
const otherPublicJwk = {
  kty: 'EC',
  crv: 'P-256',
  x: 'R7D-W2d9MEVRN_5P23yN9SodkjMEHI2Np_YHD02eTCQ',
  y: 'c5Ynunf6XyarMKXt0hWEezNzsZv01uQpCnpT-qJoll8',
}
// A key type RFC 7638 names no thumbprint members for
const akpPublicJwk = { pub: 'bWwtZHNhLXB1YmxpYy1rZXk', kty: 'AKP', alg: 'ML-DSA-44' }

const x5cSigner = { method: 'x5c', alg: 'ES256', x5c } satisfies JwsSigner
const jwkSigner = { method: 'jwk', alg: 'ES256', publicJwk: jwsPublicJwk } satisfies JwsSigner
const akpJwkSigner = { method: 'jwk', alg: 'ML-DSA-44', publicJwk: akpPublicJwk } satisfies JwsSigner
const didSigner = { method: 'did', alg: 'ES256', didUrl } satisfies JwsSigner
const customSigner = { method: 'custom', alg: 'ES256', kid: 'status-list-key-1' } satisfies JwsSigner
const federationSigner = {
  method: 'federation',
  alg: 'ES256',
  kid: 'status-list-key-1',
  trustChain,
} satisfies JwsSigner

type SignerHeader = Record<string, unknown>

const signIssuedBy = (
  issuer: string | undefined,
  signer: JwsSigner,
  header?: SignerHeader,
  signJwsCallback: SignJwsCallback = signJws
) =>
  signJwt({
    header: { ...jwsHeaderFromSigner(signer), ...header },
    payload: issuer ? { iss: issuer } : {},
    signer,
    signJwsCallback,
  })

const sign = (signer: JwsSigner, header?: SignerHeader, signJwsCallback?: SignJwsCallback) =>
  signIssuedBy(undefined, signer, header, signJwsCallback)

const signedHeader = async (signer: JwsSigner, header?: SignerHeader) =>
  decodeJwt({ jwt: (await sign(signer, header)).jwt }).header

it('signs a header that does not identify the signer', async () => {
  const { jwt } = await signJwt({ header: {}, payload: {}, signer: x5cSigner, signJwsCallback: signJws })

  expect(decodeJwt({ jwt }).header).toEqual({ alg: 'ES256' })
})

describe('a signed header that repeats or adds to what identifies the signer', () => {
  it('is signed when it repeats the certificate chain of an x5c signer', async () => {
    expect(await signedHeader(x5cSigner, { x5c: [...x5c] })).toEqual({ alg: 'ES256', x5c })
  })

  // The same key, with members the thumbprint of a key is not computed over
  it('is signed with its own jwk when that is the public key of a jwk signer', async () => {
    const jwk = { ...jwsPublicJwk, kid: 'status-list-key-1', alg: 'ES256' }

    expect(await signedHeader(jwkSigner, { jwk })).toEqual({ alg: 'ES256', jwk })
  })

  it('is signed when it repeats a public key without an RFC 7638 thumbprint with its members in another order', async () => {
    const jwk = { alg: akpPublicJwk.alg, kty: akpPublicJwk.kty, pub: akpPublicJwk.pub }

    expect(await signedHeader(akpJwkSigner, { jwk })).toEqual({ alg: 'ML-DSA-44', jwk })
  })

  it('is signed when it repeats the DID URL of a did signer as kid', async () => {
    expect(await signedHeader(didSigner, { kid: didUrl })).toEqual({
      alg: 'ES256',
      kid: didUrl,
    })
  })

  // The kid of an x5c or jwk signer is not in the header, so a kid in the header is a hint
  it.each([
    ['an x5c signer', x5cSigner, { x5c }],
    ['a jwk signer', jwkSigner, { jwk: jwsPublicJwk }],
  ] satisfies Array<[string, JwsSigner, SignerHeader]>)(
    'is signed when it adds a kid to the header of %s',
    async (_signer, signer, signerParameters) => {
      expect(await signedHeader(signer, { kid: 'leaf-key' })).toEqual({
        alg: 'ES256',
        kid: 'leaf-key',
        ...signerParameters,
      })
    }
  )

  // A fragment as kid only identifies a did signer when a verifier can resolve it against a DID in iss
  it('is signed when it adds a fragment as kid to an x5c signer, in a token whose iss is not a DID', async () => {
    const { jwt } = await signIssuedBy('https://issuer.example', x5cSigner, { kid: '#key-1' })

    expect(decodeJwt({ jwt }).header).toEqual({ alg: 'ES256', kid: '#key-1', x5c })
  })

  // A custom signer is established out of band, so how the header identifies it is up to the caller
  it('is signed when it identifies a custom signer without a kid by jwk', async () => {
    expect(await signedHeader({ method: 'custom', alg: 'ES256' }, { jwk: jwsPublicJwk })).toEqual({
      alg: 'ES256',
      jwk: jwsPublicJwk,
    })
  })

  it('is signed when it adds a certificate chain to the kid of a custom signer', async () => {
    expect(await signedHeader(customSigner, { x5c })).toEqual({
      alg: 'ES256',
      kid: 'status-list-key-1',
      x5c,
    })
  })
})

describe('a signed header that contradicts the signer', () => {
  it.each([
    [
      'a kid other than the kid of a custom signer',
      customSigner,
      { kid: 'other-key' },
      "the kid in the header is 'other-key', but the signer is identified by kid 'status-list-key-1'",
    ],
    [
      'a kid other than the DID URL of a did signer',
      didSigner,
      { kid: 'did:example:issuer#key-2' },
      "the kid in the header is 'did:example:issuer#key-2', but the signer is identified by kid 'did:example:issuer#key-1'",
    ],
    [
      'a kid other than the kid of a federation signer',
      federationSigner,
      { kid: 'other-key' },
      "the kid in the header is 'other-key', but the signer is identified by kid 'status-list-key-1'",
    ],
    [
      'an x5c other than the certificate chain of an x5c signer',
      x5cSigner,
      { x5c: [otherCertificate, rootCertificate] },
      'the x5c in the header is not the certificate chain of the signer',
    ],
    [
      'an x5c that leaves a certificate out of the chain of an x5c signer',
      x5cSigner,
      { x5c: [x5c[0]] },
      'the x5c in the header is not the certificate chain of the signer',
    ],
    [
      'a jwk other than the public key of a jwk signer',
      jwkSigner,
      { jwk: otherPublicJwk },
      'the jwk in the header is not the public key of the signer',
    ],
    [
      'a jwk other than a public key without an RFC 7638 thumbprint',
      akpJwkSigner,
      { jwk: { ...akpPublicJwk, pub: 'b3RoZXItbWwtZHNhLWtleQ' } },
      'the jwk in the header is not the public key of the signer',
    ],
    [
      'a trust_chain other than the trust chain of a federation signer',
      federationSigner,
      { trust_chain: ['other-entity-statement'] },
      'the trust_chain in the header is not the trust chain of the signer',
    ],
  ] satisfies Array<[string, JwsSigner, SignerHeader, string]>)(
    'is rejected for %s',
    async (_case, signer, header, message) => {
      const signing = sign(signer, header)

      await expect(signing).rejects.toThrow(JoseInvalidArgumentError)
      await expect(signing).rejects.toThrow(message)
    }
  )

  // A verifier rejects a header that identifies the signer in two ways, even with the same key
  it.each([
    [
      'a jwk next to the certificate chain of an x5c signer',
      x5cSigner,
      { jwk: jwsPublicJwk },
      "the 'jwk' in the header identifies a signer with method 'jwk', but the signer has method 'x5c'",
    ],
    [
      'a certificate chain next to the public key of a jwk signer',
      jwkSigner,
      { x5c },
      "the 'x5c' in the header identifies a signer with method 'x5c', but the signer has method 'jwk'",
    ],
    [
      'a jwk next to the DID URL of a did signer',
      didSigner,
      { jwk: jwsPublicJwk },
      "the 'jwk' in the header identifies a signer with method 'jwk', but the signer has method 'did'",
    ],
    [
      'a trust chain next to the certificate chain of an x5c signer',
      x5cSigner,
      { trust_chain: trustChain },
      "the 'trust_chain' in the header identifies a signer with method 'federation', but the signer has method 'x5c'",
    ],
    [
      'a certificate chain next to the kid and trust chain of a federation signer',
      federationSigner,
      { x5c },
      "the 'x5c' in the header identifies a signer with method 'x5c', but the signer has method 'federation'",
    ],
    [
      'a DID URL as the kid of an x5c signer',
      x5cSigner,
      { kid: didUrl },
      "the 'kid' in the header identifies a signer with method 'did', but the signer has method 'x5c'",
    ],
  ] satisfies Array<[string, JwsSigner, SignerHeader, string]>)(
    'is rejected for %s',
    async (_case, signer, header, message) => {
      const signing = sign(signer, header)

      await expect(signing).rejects.toThrow(JoseInvalidArgumentError)
      await expect(signing).rejects.toThrow(message)
    }
  )

  // A verifier resolves a fragment kid against a DID iss, so it identifies a did signer
  it.each([
    ['an x5c signer', x5cSigner, { kid: '#key-1' }, 'x5c'],
    ['a jwk signer', jwkSigner, { kid: '#key-1' }, 'jwk'],
    ['a federation signer', { method: 'federation', alg: 'ES256', kid: '#key-1' }, undefined, 'federation'],
  ] satisfies Array<[string, JwsSigner, SignerHeader | undefined, string]>)(
    'is rejected for a fragment as kid next to %s, in a token whose iss is a DID',
    async (_signer, signer, header, method) => {
      const signing = signIssuedBy('did:example:issuer', signer, header)

      await expect(signing).rejects.toThrow(JoseInvalidArgumentError)
      await expect(signing).rejects.toThrow(
        `the 'kid' in the header identifies a signer with method 'did', but the signer has method '${method}'`
      )
    }
  )

  it('is rejected before the signing callback is called', async () => {
    const signJwsCallback = vi.fn(signJws)

    await expect(sign(x5cSigner, { x5c: [otherCertificate] }, signJwsCallback)).rejects.toThrow(
      JoseInvalidArgumentError
    )
    expect(signJwsCallback).not.toHaveBeenCalled()
  })
})
