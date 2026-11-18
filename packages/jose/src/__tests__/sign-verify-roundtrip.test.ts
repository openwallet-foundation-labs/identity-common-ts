import { base64url, stringToBytes } from '@owf/identity-common'
import * as referenceJose from 'jose'
import { describe, expect, it } from 'vitest'
import type { SignJwsCallback, SignJwsCallbackContext, VerifyJwsCallback, VerifyJwsCallbackContext } from '../callbacks'
import { JoseSignatureVerificationError } from '../error'
import type { Jwk } from '../jwk/z-jwk'
import { parseJws } from '../jws/parse-jws'
import { signCompactJws } from '../jws/sign-jws'
import { verifyJwsSignature } from '../jws/verify-jws'
import { signJwt } from '../jwt/sign-jwt'
import { verifyJwt } from '../jwt/verify-jwt'
import { validationIssue } from './context'

/**
 * Signing and verifying with real keys, through WebCrypto, for each algorithm a deployment is likely
 * to use, and against `jose` as an independent implementation: a token this package signs has to
 * verify elsewhere, and the other way around.
 *
 * Every algorithm here is available in the WebCrypto of the Node.js versions this package supports,
 * so none of them is skipped.
 */

/** Matches a thrown error by its class and a part of its message. */
const joseError = (type: { name: string }, message: string) =>
  expect.objectContaining({ name: type.name, message: expect.stringContaining(message) })

const rsaKeyGenParams = { modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' }

const webCryptoAlgorithms = {
  ES256: { generate: { name: 'ECDSA', namedCurve: 'P-256' }, sign: { name: 'ECDSA', hash: 'SHA-256' } },
  ES384: { generate: { name: 'ECDSA', namedCurve: 'P-384' }, sign: { name: 'ECDSA', hash: 'SHA-384' } },
  ES512: { generate: { name: 'ECDSA', namedCurve: 'P-521' }, sign: { name: 'ECDSA', hash: 'SHA-512' } },
  RS256: { generate: { name: 'RSASSA-PKCS1-v1_5', ...rsaKeyGenParams }, sign: { name: 'RSASSA-PKCS1-v1_5' } },
  PS256: { generate: { name: 'RSA-PSS', ...rsaKeyGenParams }, sign: { name: 'RSA-PSS', saltLength: 32 } },
  EdDSA: { generate: { name: 'Ed25519' }, sign: { name: 'Ed25519' } },
  Ed25519: { generate: { name: 'Ed25519' }, sign: { name: 'Ed25519' } },
} satisfies Record<string, { generate: AlgorithmIdentifier | EcKeyGenParams | RsaHashedKeyGenParams; sign: object }>

type Algorithm = keyof typeof webCryptoAlgorithms

interface WebCryptoSigner {
  alg: Algorithm
  keyPair: CryptoKeyPair
  publicJwk: Jwk
  signJws: SignJwsCallback
  verifyJws: VerifyJwsCallback
}

async function createSigner(alg: Algorithm): Promise<WebCryptoSigner> {
  const { generate, sign } = webCryptoAlgorithms[alg]
  const keyPair = (await globalThis.crypto.subtle.generateKey(generate, true, ['sign', 'verify'])) as CryptoKeyPair

  // `ext` and `key_ops` say nothing about the key itself, and `alg` is left out because WebCrypto
  // names an Ed25519 key 'Ed25519' while a token may use the polymorphic 'EdDSA' for it
  const exported = (await globalThis.crypto.subtle.exportKey('jwk', keyPair.publicKey)) as Jwk
  const { ext: _ext, key_ops: _keyOps, alg: _alg, ...publicJwk } = exported

  const signJws: SignJwsCallback = async (_signer, { signingInputBytes }) => {
    const signature = await globalThis.crypto.subtle.sign(
      sign,
      keyPair.privateKey,
      signingInputBytes as Uint8Array<ArrayBuffer>
    )

    return { signature: base64url.encode(new Uint8Array(signature)), signerJwk: publicJwk }
  }

  const verifyJws: VerifyJwsCallback = async (_signer, { signingInputBytes, signature }) => {
    const verified = await globalThis.crypto.subtle.verify(
      sign,
      keyPair.publicKey,
      base64url.decode(signature) as Uint8Array<ArrayBuffer>,
      signingInputBytes as Uint8Array<ArrayBuffer>
    )

    return verified ? { verified: true, signerJwk: publicJwk } : { verified: false }
  }

  return { alg, keyPair, publicJwk, signJws, verifyJws }
}

// Generating an RSA key takes a while, so every algorithm gets one key for all of its tests
const signers = new Map<Algorithm, Promise<WebCryptoSigner>>()
const signerFor = (alg: Algorithm) => {
  const signer = signers.get(alg) ?? createSigner(alg)
  signers.set(alg, signer)
  return signer
}

const now = new Date('2026-09-15T12:00:00Z')
const iat = now.getTime() / 1000

/** The same base64url string with its first character changed, which changes the first byte. */
const alterFirstCharacter = (value: string) => `${value[0] === 'A' ? 'B' : 'A'}${value.slice(1)}`

describe.each(Object.keys(webCryptoAlgorithms) as Algorithm[])('%s', (alg) => {
  it('verifies a compact JWS it signed, establishing the signer from the jwk header parameter', async () => {
    const { publicJwk, signJws, verifyJws } = await signerFor(alg)
    const { compact } = await signCompactJws({
      protectedHeader: { alg, jwk: publicJwk },
      payload: { hello: 'world' },
      signer: { method: 'jwk', alg, publicJwk },
      signJwsCallback: signJws,
    })

    const { signer } = await verifyJwsSignature({
      jws: parseJws({ jws: compact }),
      verifyJwsCallback: verifyJws,
      allowedAlgorithms: [alg],
    })

    expect(signer).toEqual({ method: 'jwk', alg, publicJwk })
  })

  it('verifies a JWT it signed', async () => {
    const { signJws, verifyJws } = await signerFor(alg)
    const { jwt } = await signJwt({
      header: { typ: 'example+jwt' },
      payload: { iss: 'https://issuer.example', iat },
      signer: { method: 'custom', alg },
      signJwsCallback: signJws,
    })

    const { header, payload } = await verifyJwt({
      jwt,
      verifyJwsCallback: verifyJws,
      allowedAlgorithms: [alg],
      expectedIssuer: 'https://issuer.example',
      now,
    })

    expect([header, payload]).toEqual([
      { typ: 'example+jwt', alg },
      { iss: 'https://issuer.example', iat },
    ])
  })

  it('verifies the flattened JSON serialization of a compact JWS it signed', async () => {
    const { signJws, verifyJws } = await signerFor(alg)
    const { compact } = await signCompactJws({
      protectedHeader: { alg },
      payload: 'the payload',
      signer: { method: 'custom', alg },
      signJwsCallback: signJws,
    })
    const [protectedHeader, payload, signature] = compact.split('.')

    const jws = parseJws({ jws: { protected: protectedHeader, payload, signature } })
    await verifyJwsSignature({ jws, verifyJwsCallback: verifyJws })

    expect(jws.payload).toEqual(stringToBytes('the payload'))
  })

  it('verifies a JWS it signed with a detached payload', async () => {
    const { signJws, verifyJws } = await signerFor(alg)
    const { compact } = await signCompactJws({
      protectedHeader: { alg },
      payload: new Uint8Array([0, 1, 254, 255]),
      signer: { method: 'custom', alg },
      signJwsCallback: signJws,
      detachPayload: true,
    })

    const jws = parseJws({ jws: compact, detachedPayload: new Uint8Array([0, 1, 254, 255]) })
    const { signer } = await verifyJwsSignature({ jws, verifyJwsCallback: verifyJws })

    expect(signer.alg).toBe(alg)
  })

  it('rejects the signature over a detached payload for another payload', async () => {
    const { signJws, verifyJws } = await signerFor(alg)
    const { compact } = await signCompactJws({
      protectedHeader: { alg },
      payload: new Uint8Array([0, 1, 254, 255]),
      signer: { method: 'custom', alg },
      signJwsCallback: signJws,
      detachPayload: true,
    })

    const jws = parseJws({ jws: compact, detachedPayload: new Uint8Array([0, 1, 254, 254]) })

    await expect(verifyJwsSignature({ jws, verifyJwsCallback: verifyJws })).rejects.toThrow(
      joseError(JoseSignatureVerificationError, 'Error during verification of the JWS.')
    )
  })

  it('rejects a JWT whose signature was altered', async () => {
    const { signJws, verifyJws } = await signerFor(alg)
    const { jwt } = await signJwt({
      payload: { iss: 'https://issuer.example' },
      signer: { method: 'custom', alg },
      signJwsCallback: signJws,
    })
    const [header, payload, signature] = jwt.split('.')

    await expect(
      verifyJwt({ jwt: `${header}.${payload}.${alterFirstCharacter(signature)}`, verifyJwsCallback: verifyJws, now })
    ).rejects.toThrow(joseError(JoseSignatureVerificationError, 'Error during verification of the JWT.'))
  })

  it('signs a JWT that an independent JOSE implementation verifies', async () => {
    const { keyPair, signJws } = await signerFor(alg)
    const { jwt } = await signJwt({
      header: { typ: 'example+jwt' },
      payload: { iss: 'https://issuer.example', iat },
      signer: { method: 'custom', alg },
      signJwsCallback: signJws,
    })

    const { payload } = await referenceJose.jwtVerify(jwt, keyPair.publicKey, { algorithms: [alg], currentDate: now })

    expect(payload).toEqual({ iss: 'https://issuer.example', iat })
  })

  it('verifies a JWT that an independent JOSE implementation signed', async () => {
    const { keyPair, verifyJws } = await signerFor(alg)
    const jwt = await new referenceJose.SignJWT({ iss: 'https://issuer.example', iat })
      .setProtectedHeader({ alg, typ: 'example+jwt' })
      .sign(keyPair.privateKey)

    const { payload } = await verifyJwt({ jwt, verifyJwsCallback: verifyJws, allowedAlgorithms: [alg], now })

    expect(payload).toEqual({ iss: 'https://issuer.example', iat })
  })
})

describe('private key material', () => {
  /** A signing callback that records whether it was called, and signs with the ES256 key otherwise. */
  const recordingSigner = async () => {
    const { signJws } = await signerFor('ES256')
    const calls: SignJwsCallbackContext[] = []
    const signJwsCallback: SignJwsCallback = (signer, context) => {
      calls.push(context)
      return signJws(signer, context)
    }

    return { calls, signJwsCallback }
  }

  it('is never signed into the jwk header parameter', async () => {
    const { publicJwk } = await signerFor('ES256')
    const { calls, signJwsCallback } = await recordingSigner()

    await expect(
      signCompactJws({
        protectedHeader: { alg: 'ES256', jwk: { ...publicJwk, d: 'cHJpdmF0ZQ' } },
        payload: 'the payload',
        signer: { method: 'custom', alg: 'ES256' },
        signJwsCallback,
      })
    ).rejects.toThrow(validationIssue(['jwk', 'd'], 'not_allowed'))
    expect(calls).toEqual([])
  })

  it('is never signed into the cnf claim of a JWT', async () => {
    const { publicJwk } = await signerFor('ES256')
    const { calls, signJwsCallback } = await recordingSigner()

    await expect(
      signJwt({
        payload: { iss: 'https://issuer.example', cnf: { jwk: { ...publicJwk, d: 'cHJpdmF0ZQ' } } },
        signer: { method: 'custom', alg: 'ES256' },
        signJwsCallback,
      })
    ).rejects.toThrow(validationIssue(['cnf', 'jwk', 'd'], 'not_allowed'))
    expect(calls).toEqual([])
  })
})

describe('what the signing callback is given', () => {
  /** Signs with ES256, keeping the context the callback was called with. */
  const signCapturingContext = async (payload: Record<string, unknown> | string | Uint8Array) => {
    const { signJws } = await signerFor('ES256')
    let context: SignJwsCallbackContext | undefined
    const result = await signCompactJws({
      protectedHeader: { alg: 'ES256', typ: 'example+jws' },
      payload,
      signer: { method: 'custom', alg: 'ES256' },
      signJwsCallback: (signer, callbackContext) => {
        context = callbackContext
        return signJws(signer, callbackContext)
      },
    })

    return { result, context: context as SignJwsCallbackContext }
  }

  it('is the signing input that ends up in the token', async () => {
    const { result, context } = await signCapturingContext({ hello: 'world' })
    const [header, payload] = result.compact.split('.')

    expect([context.signingInput, context.signingInputBytes]).toEqual([
      `${header}.${payload}`,
      stringToBytes(`${header}.${payload}`),
    ])
  })

  it('serializes an object payload as compact JSON', async () => {
    const { context } = await signCapturingContext({ hello: 'world', count: 1 })

    expect(context.payload).toEqual(stringToBytes('{"hello":"world","count":1}'))
  })

  it('includes the claims of an object payload as jwtPayload', async () => {
    const { context } = await signCapturingContext({ hello: 'world' })

    expect(context.jwtPayload).toEqual({ hello: 'world' })
  })

  it.each([
    ['a string', 'hello world'],
    ['bytes', new Uint8Array([104, 105])],
  ])('includes no jwtPayload for a payload that is %s', async (_description, payload) => {
    const { context } = await signCapturingContext(payload)

    expect(context.jwtPayload).toBeUndefined()
  })
})

describe('what the verification callback is given', () => {
  it('includes the claims of a JWT as jwtPayload', async () => {
    const { signJws, verifyJws } = await signerFor('ES256')
    const { jwt } = await signJwt({
      payload: { iss: 'https://issuer.example', iat },
      signer: { method: 'custom', alg: 'ES256' },
      signJwsCallback: signJws,
    })
    let context: VerifyJwsCallbackContext | undefined

    await verifyJwt({
      jwt,
      verifyJwsCallback: (signer, callbackContext) => {
        context = callbackContext
        return verifyJws(signer, callbackContext)
      },
      now,
    })

    expect(context?.jwtPayload).toEqual({ iss: 'https://issuer.example', iat })
  })
})

describe('an unencoded payload (RFC 7797) and an independent JOSE implementation', () => {
  const protectedHeader = { alg: 'ES256', b64: false, crit: ['b64'] }

  it('is signed in a way an independent JOSE implementation verifies', async () => {
    const { keyPair, signJws } = await signerFor('ES256')
    const { compact } = await signCompactJws({
      protectedHeader,
      payload: '$.02',
      signer: { method: 'custom', alg: 'ES256' },
      signJwsCallback: signJws,
      detachPayload: true,
    })
    const [header, , signature] = compact.split('.')

    const { payload } = await referenceJose.flattenedVerify(
      { protected: header, payload: '$.02', signature },
      keyPair.publicKey
    )

    expect(payload).toEqual(stringToBytes('$.02'))
  })

  it('verifies when an independent JOSE implementation signed it', async () => {
    const { keyPair, verifyJws } = await signerFor('ES256')
    const signed = await new referenceJose.FlattenedSign(stringToBytes('$.02'))
      .setProtectedHeader(protectedHeader)
      .sign(keyPair.privateKey)

    // `jose` leaves the unencoded payload out, and RFC 7515 Appendix F detaches a payload from a JSON
    // serialization by removing the member altogether
    const { payload: _payload, ...detached } = signed
    const jws = parseJws({ jws: detached, detachedPayload: '$.02', understoodCriticalParameters: ['b64'] })
    const { signer } = await verifyJwsSignature({ jws, verifyJwsCallback: verifyJws })

    expect(signer.alg).toBe('ES256')
  })
})
