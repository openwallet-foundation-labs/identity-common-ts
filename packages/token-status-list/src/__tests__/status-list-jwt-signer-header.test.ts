import type { JwsSigner } from '@owf/jose'
import { describe, expect, it } from 'vitest'
import { JWT_STATUS_LIST_TYPE } from '../jwt-types'
import {
  decodeStatusListJwt,
  type SignStatusListJwtOptions,
  signStatusListJwt,
  verifyStatusListJwt,
} from '../status-list-jwt'
import { leafCertificate, rootCertificate } from './certificates'
import { jwsPublicJwk, signJws, verifyJws } from './context'
import { now, secondsFromNow, statusListWith, uri } from './status-list-jwt-tokens'

// The header of a signed Status List Token identifies the signer the way a verifier establishes it

type SignerHeader = NonNullable<SignStatusListJwtOptions['header']>

const x5c = [leafCertificate, rootCertificate]
const didUrl = 'did:example:issuer#key-1'
const trustChain: [string, ...string[]] = ['entity-statement', 'trust-anchor-statement']

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
