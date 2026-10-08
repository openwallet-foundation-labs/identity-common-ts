import { JoseInvalidArgumentError, type JwsSigner } from '@owf/jose'
import { describe, expect, it, vi } from 'vitest'
import { JWT_STATUS_LIST_TYPE } from '../jwt-types'
import {
  decodeStatusListJwt,
  type SignStatusListJwtOptions,
  signStatusListJwt,
  verifyStatusListJwt,
} from '../status-list-jwt'
import { leafCertificate, rfc7517Certificate, rootCertificate } from './certificates'
import { jwsPublicJwk, signJws, verifyJws } from './context'
import { now, secondsFromNow, statusListWith, uri } from './status-list-jwt-tokens'

// How `signStatusListJwt` identifies its signer in the header of a Status List Token. A verifier
// establishes the signer from the header, so a header that does not identify the signer the token is
// signed with makes a token that a verifier resolving the key from the signer cannot verify.

type SignerHeader = NonNullable<SignStatusListJwtOptions['header']>

/**
 * A certificate chain: a leaf certificate and the root that issued it. `@owf/jose` checks that each is
 * base64 encoded DER, and the callbacks of these tests do not validate the chain.
 */
const x5c = [leafCertificate, rootCertificate]
/** A certificate other than the leaf of {@link x5c}. */
const otherCertificate = rfc7517Certificate
const didUrl = 'did:example:issuer#key-1'
const trustChain: [string, ...string[]] = ['entity-statement', 'trust-anchor-statement']

/** A P-256 public key other than the one the tokens are signed with: that of `otherSignKey`. */
const otherPublicJwk = {
  kty: 'EC',
  crv: 'P-256',
  x: 'R7D-W2d9MEVRN_5P23yN9SodkjMEHI2Np_YHD02eTCQ',
  y: 'c5Ynunf6XyarMKXt0hWEezNzsZv01uQpCnpT-qJoll8',
}

/**
 * An ML-DSA public key: a key type RFC 7638 names no thumbprint members for. Its members are not in
 * the order the header schema puts them in.
 */
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

const sign = (signer: JwsSigner, header?: SignerHeader, signJwsCallback = signJws) =>
  signStatusListJwt({
    statusList: statusListWith(),
    payload: { sub: uri, iat: secondsFromNow(-60) },
    header,
    signer,
    signJwsCallback,
  })

/** The header of the Status List Token signed by `signer`, as a verifier decodes it. */
const signedHeader = async (signer: JwsSigner, header?: SignerHeader) =>
  decodeStatusListJwt((await sign(signer, header)).jwt).header

/** Signs a Status List Token whose `iss` is `issuer`. */
const signIssuedBy = (issuer: string, signer: JwsSigner, header?: SignerHeader) =>
  signStatusListJwt({
    statusList: statusListWith(),
    payload: { iss: issuer, sub: uri, iat: secondsFromNow(-60) },
    header,
    signer,
    signJwsCallback: signJws,
  })

describe('the header of a Status List Token signed by signStatusListJwt', () => {
  it('carries the certificate chain of an x5c signer', async () => {
    expect(await signedHeader(x5cSigner)).toEqual({ alg: 'ES256', typ: JWT_STATUS_LIST_TYPE, x5c })
  })

  it('carries the public key of a jwk signer', async () => {
    expect(await signedHeader(jwkSigner)).toEqual({ alg: 'ES256', typ: JWT_STATUS_LIST_TYPE, jwk: jwsPublicJwk })
  })

  it('carries the public key of a jwk signer whose key type has no RFC 7638 thumbprint', async () => {
    expect(await signedHeader(akpJwkSigner)).toEqual({
      alg: 'ML-DSA-44',
      typ: JWT_STATUS_LIST_TYPE,
      jwk: akpPublicJwk,
    })
  })

  it('carries the DID URL of a did signer as kid', async () => {
    expect(await signedHeader(didSigner)).toEqual({ alg: 'ES256', typ: JWT_STATUS_LIST_TYPE, kid: didUrl })
  })

  it('carries the kid of a custom signer', async () => {
    expect(await signedHeader(customSigner)).toEqual({
      alg: 'ES256',
      typ: JWT_STATUS_LIST_TYPE,
      kid: 'status-list-key-1',
    })
  })

  it('carries the kid and the trust chain of a federation signer', async () => {
    expect(await signedHeader(federationSigner)).toEqual({
      alg: 'ES256',
      typ: JWT_STATUS_LIST_TYPE,
      kid: 'status-list-key-1',
      trust_chain: trustChain,
    })
  })

  it('carries only alg and typ for a custom signer without a kid', async () => {
    expect(await signedHeader({ method: 'custom', alg: 'ES256' })).toEqual({ alg: 'ES256', typ: JWT_STATUS_LIST_TYPE })
  })

  it('keeps the certificate chain of an x5c signer when the header sets x5c to undefined', async () => {
    expect(await signedHeader(x5cSigner, { x5c: undefined })).toEqual({ alg: 'ES256', typ: JWT_STATUS_LIST_TYPE, x5c })
  })

  it('keeps the kid of a custom signer when the header sets kid to undefined', async () => {
    expect(await signedHeader(customSigner, { kid: undefined })).toEqual({
      alg: 'ES256',
      typ: JWT_STATUS_LIST_TYPE,
      kid: 'status-list-key-1',
    })
  })
})

describe('a Status List Token signed by signStatusListJwt', () => {
  it.each([
    ['x5c', x5cSigner],
    ['jwk', jwkSigner],
    ['did', didSigner],
    ['custom', customSigner],
    ['federation', federationSigner],
  ] satisfies Array<[string, JwsSigner]>)(
    'is verified by verifyStatusListJwt against the %s signer its header identifies',
    async (_method, signer) => {
      const { jwt } = await sign(signer)

      const verified = await verifyStatusListJwt({ jwt, uri, now, verifyJwsCallback: verifyJws })

      expect(verified.signer).toEqual({ ...signer, publicJwk: jwsPublicJwk })
    }
  )
})

describe('a header passed to signStatusListJwt that repeats or adds to what identifies the signer', () => {
  it('is signed when it repeats the certificate chain of an x5c signer', async () => {
    expect(await signedHeader(x5cSigner, { x5c: [...x5c] })).toEqual({ alg: 'ES256', typ: JWT_STATUS_LIST_TYPE, x5c })
  })

  // The same key, with members the thumbprint of a key is not computed over
  it('is signed with its own jwk when that is the public key of a jwk signer', async () => {
    const jwk = { ...jwsPublicJwk, kid: 'status-list-key-1', alg: 'ES256' }

    expect(await signedHeader(jwkSigner, { jwk })).toEqual({ alg: 'ES256', typ: JWT_STATUS_LIST_TYPE, jwk })
  })

  it('is signed when it repeats a public key without an RFC 7638 thumbprint with its members in another order', async () => {
    const jwk = { alg: akpPublicJwk.alg, kty: akpPublicJwk.kty, pub: akpPublicJwk.pub }

    expect(await signedHeader(akpJwkSigner, { jwk })).toEqual({ alg: 'ML-DSA-44', typ: JWT_STATUS_LIST_TYPE, jwk })
  })

  it('is signed when it repeats the DID URL of a did signer as kid', async () => {
    expect(await signedHeader(didSigner, { kid: didUrl })).toEqual({
      alg: 'ES256',
      typ: JWT_STATUS_LIST_TYPE,
      kid: didUrl,
    })
  })

  // `@owf/jose` does not put the kid of an x5c or jwk signer in the header: it says which key the
  // callback signs with, so the kid of the header is a hint that does not contradict it
  it.each([
    ['an x5c signer', x5cSigner, { x5c }],
    ['a jwk signer', jwkSigner, { jwk: jwsPublicJwk }],
  ] satisfies Array<[string, JwsSigner, SignerHeader]>)(
    'is signed when it adds a kid to the header of %s',
    async (_signer, signer, signerParameters) => {
      expect(await signedHeader(signer, { kid: 'leaf-key' })).toEqual({
        alg: 'ES256',
        typ: JWT_STATUS_LIST_TYPE,
        kid: 'leaf-key',
        ...signerParameters,
      })
    }
  )

  // A fragment as kid only identifies a did signer when a verifier can resolve it against a DID in iss
  it('is signed when it adds a fragment as kid to an x5c signer, in a token whose iss is not a DID', async () => {
    const { jwt } = await signIssuedBy('https://issuer.example', x5cSigner, { kid: '#key-1' })

    expect(decodeStatusListJwt(jwt).header).toEqual({ alg: 'ES256', typ: JWT_STATUS_LIST_TYPE, kid: '#key-1', x5c })
  })

  // A custom signer is established out of band, so how the header identifies it is up to the caller
  it('is signed when it identifies a custom signer without a kid by jwk', async () => {
    expect(await signedHeader({ method: 'custom', alg: 'ES256' }, { jwk: jwsPublicJwk })).toEqual({
      alg: 'ES256',
      typ: JWT_STATUS_LIST_TYPE,
      jwk: jwsPublicJwk,
    })
  })

  it('is signed when it adds a certificate chain to the kid of a custom signer', async () => {
    expect(await signedHeader(customSigner, { x5c })).toEqual({
      alg: 'ES256',
      typ: JWT_STATUS_LIST_TYPE,
      kid: 'status-list-key-1',
      x5c,
    })
  })
})

describe('a header passed to signStatusListJwt that contradicts the signer', () => {
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

  // Whether a key next to the one the signer is identified by is the same key cannot be told, and a
  // verifier rejects a header that identifies the signer in more than one way. The jwk here is in fact
  // the key the token is signed with.
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

  // A verifier resolves a fragment as kid against a DID in iss, so it identifies a did signer as much as
  // a DID URL does: next to an x5c or jwk the header is ambiguous, and next to the kid of a federation
  // signer without a trust chain it makes a verifier establish a did signer instead
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
