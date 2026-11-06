import { bytesToString } from '@owf/identity-common'
import * as referenceJose from 'jose'
import { describe, expect, it } from 'vitest'
import { JoseInvalidArgumentError } from '../error'
import { parseJws } from '../jws/parse-jws'
import { signFlattenedJws, signGeneralJws } from '../jws/sign-jws'
import type { JwsSigner } from '../jws/signer'
import { verifyJwsSignature } from '../jws/verify-jws'
import { createEs256Context, validationIssue } from './context'

const { publicJwk, signJws, verifyJws } = await createEs256Context()
const signer: JwsSigner = { method: 'jwk', alg: 'ES256', publicJwk }
const referenceKey = await referenceJose.importJWK(publicJwk, 'ES256')

describe('signFlattenedJws', () => {
  it('signs a JWS with an unprotected header that the reference library and parseJws verify', async () => {
    const { jws } = await signFlattenedJws({
      protectedHeader: { alg: 'ES256', jwk: publicJwk },
      unprotectedHeader: { etsiU: ['note'] },
      payload: { iss: 'https://issuer.example' },
      signer,
      signJwsCallback: signJws,
    })

    const reference = await referenceJose.flattenedVerify(jws as referenceJose.FlattenedJWSInput, referenceKey)
    expect(JSON.parse(bytesToString(reference.payload))).toEqual({ iss: 'https://issuer.example' })
    expect(reference.unprotectedHeader).toEqual({ etsiU: ['note'] })

    const parsed = parseJws({ jws })
    expect(parsed.serialization).toBe('flattened')
    await expect(verifyJwsSignature({ jws: parsed, verifyJwsCallback: verifyJws })).resolves.toBeDefined()
  })

  it('leaves out a detached payload, and carries an unencoded payload with a period', async () => {
    const detached = await signFlattenedJws({
      protectedHeader: { alg: 'ES256' },
      payload: 'detached',
      signer,
      signJwsCallback: signJws,
      detachPayload: true,
    })
    expect(detached.jws.payload).toBeUndefined()
    await expect(
      referenceJose.flattenedVerify({ ...detached.jws, payload: 'ZGV0YWNoZWQ' }, referenceKey)
    ).resolves.toBeDefined()

    // RFC 7797 section 5.2 only limits the payload of a compact serialization
    const unencoded = await signFlattenedJws({
      protectedHeader: { alg: 'ES256', b64: false, crit: ['b64'] },
      payload: 'a.b',
      signer,
      signJwsCallback: signJws,
    })
    expect(unencoded.jws.payload).toBe('a.b')
    await expect(
      referenceJose.flattenedVerify(unencoded.jws as referenceJose.FlattenedJWSInput, referenceKey)
    ).resolves.toBeDefined()
  })

  it('rejects a parameter in both headers, and crit in the unprotected header', async () => {
    const sign = (unprotectedHeader: Record<string, unknown>) =>
      signFlattenedJws({
        protectedHeader: { alg: 'ES256', kid: 'key-1' },
        unprotectedHeader,
        payload: 'payload',
        signer,
        signJwsCallback: signJws,
      })

    await expect(sign({ kid: 'key-2' })).rejects.toThrow(JoseInvalidArgumentError)
    await expect(sign({ crit: ['example'] })).rejects.toThrow(validationIssue(['crit'], 'invalid_crit'))
  })
})

describe('signGeneralJws', () => {
  it('signs one payload with several signatures', async () => {
    const second = await createEs256Context()

    const { jws, signatures } = await signGeneralJws({
      payload: 'payload',
      signJwsCallback: async (jwsSigner, context) =>
        jwsSigner.method === 'jwk' && jwsSigner.publicJwk === second.publicJwk
          ? second.signJws(jwsSigner, context)
          : signJws(jwsSigner, context),
      signatures: [
        { protectedHeader: { alg: 'ES256' }, unprotectedHeader: { kid: 'first' }, signer },
        {
          protectedHeader: { alg: 'ES256' },
          unprotectedHeader: { kid: 'second' },
          signer: { method: 'jwk', alg: 'ES256', publicJwk: second.publicJwk },
        },
      ],
    })

    expect(jws.signatures).toHaveLength(2)
    expect(signatures.map(({ signerJwk }) => signerJwk)).toEqual([publicJwk, second.publicJwk])
    await expect(referenceJose.generalVerify(jws as referenceJose.GeneralJWSInput, referenceKey)).resolves.toBeDefined()
    await expect(
      verifyJwsSignature({ jws: parseJws({ jws, signatureIndex: 1 }), verifyJwsCallback: second.verifyJws })
    ).resolves.toBeDefined()
  })

  it('rejects signatures that encode the payload differently', async () => {
    await expect(
      signGeneralJws({
        payload: 'payload',
        signJwsCallback: signJws,
        signatures: [
          { protectedHeader: { alg: 'ES256' }, signer },
          { protectedHeader: { alg: 'ES256', b64: false, crit: ['b64'] }, signer },
        ],
      })
    ).rejects.toThrow('same b64 value')
  })
})
