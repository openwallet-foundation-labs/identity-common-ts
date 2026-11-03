import { base64url, stringToBytes } from '@owf/identity-common'
import * as referenceJose from 'jose'
import { describe, expect, it } from 'vitest'
import z from 'zod'
import type { VerifyJwsCallback, VerifyJwsCallbackContext } from '../callbacks'
import { JoseParseError, JoseSignatureVerificationError, JoseValidationError } from '../error'
import type { Jwk } from '../jwk/z-jwk'
import { parseJws } from '../jws/parse-jws'
import { signCompactJws } from '../jws/sign-jws'
import { verifyJwsSignature } from '../jws/verify-jws'
import type { FlattenedJws, GeneralJws } from '../jws/z-jws'
import { createEs256Context, validationIssue } from './context'

/** Matches a thrown error by its class and a part of its message. */
const joseError = (type: { name: string }, message: string) =>
  expect.objectContaining({ name: type.name, message: expect.stringContaining(message) })

const encodeJson = (value: unknown) => base64url.encode(stringToBytes(JSON.stringify(value)))

const protectedHeader = encodeJson({ alg: 'ES256' })
const payload = encodeJson({ iss: 'https://issuer.example' })
const signature = 'c2lnbmF0dXJl'

/** A verification callback for a WebCrypto public key, as `jose` generates one. */
const verifierFor = async (publicKey: CryptoKey, params: Algorithm | EcdsaParams): Promise<VerifyJwsCallback> => {
  const signerJwk = (await referenceJose.exportJWK(publicKey)) as Jwk

  return async (_signer, { signingInputBytes, signature }) => {
    const verified = await globalThis.crypto.subtle.verify(
      params,
      publicKey,
      base64url.decode(signature) as Uint8Array<ArrayBuffer>,
      signingInputBytes as Uint8Array<ArrayBuffer>
    )

    return verified ? { verified: true, signerJwk } : { verified: false }
  }
}

/** A general JWS over one payload, signed by an ES256 key and an Ed25519 key with `jose`. */
const createGeneralJws = async () => {
  const es256 = await referenceJose.generateKeyPair('ES256')
  const ed25519 = await referenceJose.generateKeyPair('Ed25519')

  const general = await new referenceJose.GeneralSign(stringToBytes('{"iss":"https://issuer.example"}'))
    .addSignature(es256.privateKey)
    .setProtectedHeader({ alg: 'ES256' })
    .setUnprotectedHeader({ kid: 'es256-key' })
    .addSignature(ed25519.privateKey)
    .setProtectedHeader({ alg: 'Ed25519' })
    .setUnprotectedHeader({ kid: 'ed25519-key' })
    .sign()

  return {
    // As a recipient has it, after parsing it from JSON
    general: JSON.parse(JSON.stringify(general)) as GeneralJws,
    verifyEs256: await verifierFor(es256.publicKey, { name: 'ECDSA', hash: 'SHA-256' }),
    verifyEd25519: await verifierFor(ed25519.publicKey, { name: 'Ed25519' }),
  }
}

describe('the flattened JSON serialization', () => {
  it.each([
    ['a padded protected header', { protected: `${protectedHeader}=`, payload, signature }, 'protected'],
    ['a padded signature', { protected: protectedHeader, payload, signature: `${signature}==` }, 'signature'],
    ['a protected header in the standard base64 alphabet', { protected: 'ey+/', payload, signature }, 'protected'],
  ])('rejects %s', (_description, jws, member) => {
    expect(() => parseJws({ jws })).toThrow(validationIssue([member], 'invalid_format'))
  })

  it('rejects a carried payload that is not base64url', () => {
    expect(() => parseJws({ jws: { protected: protectedHeader, payload: 'ey+/', signature } })).toThrow(
      joseError(JoseParseError, 'Unable to decode the JWS payload, it is not valid base64url')
    )
  })

  it('rejects an unprotected header that is not an object', () => {
    const jws = { protected: protectedHeader, header: 'key-1', payload, signature } as unknown as FlattenedJws

    expect(() => parseJws({ jws })).toThrow(
      joseError(JoseValidationError, 'Unable to parse the flattened JSON serialized JWS')
    )
  })

  it('validates the unprotected header with the schema given for it', () => {
    const jws = { protected: protectedHeader, header: { kid: 1 }, payload, signature }

    expect(() => parseJws({ jws, unprotectedHeaderSchema: z.object({ kid: z.string() }) })).toThrow(
      joseError(JoseValidationError, 'Invalid JWS unprotected header')
    )
  })

  it('rejects a JWS without a payload when no detached payload is given', () => {
    expect(() => parseJws({ jws: { protected: protectedHeader, signature } })).toThrow(
      joseError(JoseParseError, 'The JWS does not carry a payload and no detached payload was provided')
    )
  })

  it('rejects a detached payload for a JWS that carries its payload', () => {
    expect(() =>
      parseJws({ jws: { protected: protectedHeader, payload, signature }, detachedPayload: 'another payload' })
    ).toThrow(joseError(JoseParseError, 'Only one of the two can be the payload that was signed'))
  })

  it('verifies a JWS whose payload member was removed to detach the payload', async () => {
    const { signJws, verifyJws } = await createEs256Context()
    const { compact } = await signCompactJws({
      protectedHeader: { alg: 'ES256' },
      payload: 'the payload',
      signer: { method: 'custom', alg: 'ES256' },
      signJwsCallback: signJws,
    })
    const [header, , detachedSignature] = compact.split('.')

    const jws = parseJws({ jws: { protected: header, signature: detachedSignature }, detachedPayload: 'the payload' })
    const { signer } = await verifyJwsSignature({ jws, verifyJwsCallback: verifyJws })

    expect(signer.alg).toBe('ES256')
  })

  it('gives the verification callback the unprotected header, and no compact serialization', async () => {
    const { signJws, verifyJws } = await createEs256Context()
    const { compact } = await signCompactJws({
      protectedHeader: { alg: 'ES256' },
      payload: 'the payload',
      signer: { method: 'custom', alg: 'ES256' },
      signJwsCallback: signJws,
    })
    const [header, encodedPayload, flattenedSignature] = compact.split('.')
    let context: VerifyJwsCallbackContext | undefined

    await verifyJwsSignature({
      jws: parseJws({
        jws: { protected: header, header: { kid: 'key-1' }, payload: encodedPayload, signature: flattenedSignature },
      }),
      verifyJwsCallback: (signer, callbackContext) => {
        context = callbackContext
        return verifyJws(signer, callbackContext)
      },
    })

    expect([context?.unprotectedHeader, context?.compact]).toEqual([{ kid: 'key-1' }, undefined])
  })

  it('verifies a flattened JWS that an independent JOSE implementation signed', async () => {
    const { privateKey, publicKey } = await referenceJose.generateKeyPair('ES256')
    const flattened = await new referenceJose.FlattenedSign(stringToBytes('the payload'))
      .setProtectedHeader({ alg: 'ES256' })
      .setUnprotectedHeader({ kid: 'key-1' })
      .sign(privateKey)

    const jws = parseJws({ jws: JSON.parse(JSON.stringify(flattened)) as FlattenedJws })
    await verifyJwsSignature({
      jws,
      verifyJwsCallback: await verifierFor(publicKey, { name: 'ECDSA', hash: 'SHA-256' }),
    })

    expect(jws.payload).toEqual(stringToBytes('the payload'))
  })
})

describe('the general JSON serialization', () => {
  it('rejects a JWS without signatures', () => {
    expect(() => parseJws({ jws: { payload, signatures: [] } })).toThrow(
      joseError(JoseValidationError, 'Unable to parse the general JSON serialized JWS')
    )
  })

  it('rejects a signature with a padded protected header', () => {
    const jws = { payload, signatures: [{ protected: `${protectedHeader}=`, signature }] }

    expect(() => parseJws({ jws })).toThrow(
      joseError(JoseValidationError, 'Unable to parse the general JSON serialized JWS')
    )
  })

  it('rejects a signature index past the last signature', () => {
    const jws = {
      payload,
      signatures: [
        { protected: protectedHeader, signature },
        { protected: protectedHeader, signature },
      ],
    }

    expect(() => parseJws({ jws, signatureIndex: 2 })).toThrow(
      joseError(JoseParseError, 'it does not contain a signature at index 2. It contains 2 signature(s).')
    )
  })

  it('rejects a negative signature index', () => {
    const jws = { payload, signatures: [{ protected: protectedHeader, signature }] }

    expect(() => parseJws({ jws, signatureIndex: -1 })).toThrow(
      joseError(JoseParseError, 'it does not contain a signature at index -1.')
    )
  })

  it('verifies the first signature of a JWS that an independent JOSE implementation signed', async () => {
    const { general, verifyEs256 } = await createGeneralJws()

    const { signer } = await verifyJwsSignature({ jws: parseJws({ jws: general }), verifyJwsCallback: verifyEs256 })

    expect(signer.alg).toBe('ES256')
  })

  it('verifies the second signature of a JWS that an independent JOSE implementation signed', async () => {
    const { general, verifyEd25519 } = await createGeneralJws()

    const jws = parseJws({ jws: general, signatureIndex: 1 })
    const { signer } = await verifyJwsSignature({ jws, verifyJwsCallback: verifyEd25519 })

    expect([signer.alg, jws.unprotectedHeader]).toEqual(['Ed25519', { kid: 'ed25519-key' }])
  })

  it('rejects a signature verified against the key of another signature of the same JWS', async () => {
    const { general, verifyEs256 } = await createGeneralJws()

    const jws = parseJws({ jws: general, signatureIndex: 1 })

    await expect(verifyJwsSignature({ jws, verifyJwsCallback: verifyEs256 })).rejects.toThrow(
      joseError(JoseSignatureVerificationError, 'Error during verification of the JWS.')
    )
  })
})
