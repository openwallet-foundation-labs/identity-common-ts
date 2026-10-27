import crypto from 'node:crypto'
import { type CallbackContext, type Jwk, Oauth2ServerErrorResponseError } from '@openid4vc/oauth2'
import * as jose from 'jose'
import { describe, expect, test, vi } from 'vitest'
import {
  type DecryptCredentialRequestOptions,
  decryptCredentialRequest,
} from '../../credential-request/decrypt-credential-request'
import { parseCredentialRequestPayload } from '../../credential-request/parse-credential-request-payload'
import { parseDeferredCredentialRequestPayload } from '../../credential-request/parse-deferred-credential-request-payload'
import type { IssuerMetadataResult } from '../../metadata/fetch-issuer-metadata'
import { Openid4vciVersion } from '../../version'

const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' })
const jwk: Jwk & { kid: string; alg: string } = {
  ...(publicKey.export({ format: 'jwk' }) as Jwk),
  kid: 'issuer-key',
  alg: 'ECDH-ES',
}

const issuerMetadata = {
  originalDraftVersion: Openid4vciVersion.V1,
  credentialIssuer: {
    credential_issuer: 'https://issuer.example',
    credential_endpoint: 'https://issuer.example/credential',
    credential_configurations_supported: {},
    credential_request_encryption: {
      jwks: { keys: [jwk] },
      enc_values_supported: ['A128GCM', 'A256GCM'],
      encryption_required: false,
    },
    credential_response_encryption: {
      alg_values_supported: ['ECDH-ES'],
      enc_values_supported: ['A128GCM'],
      encryption_required: false,
    },
  },
  authorizationServers: [],
  knownCredentialConfigurations: {},
} satisfies IssuerMetadataResult

const decryptJwe: CallbackContext['decryptJwe'] = async (jwe) => {
  try {
    const { plaintext } = await jose.compactDecrypt(jwe, privateKey)
    return { decrypted: true, payload: new TextDecoder().decode(plaintext), decryptionJwk: jwk }
  } catch (error) {
    if (error instanceof jose.errors.JWEDecryptionFailed) return { decrypted: false }
    throw error
  }
}

const callbacks = { decryptJwe }
const responseEncryption = { jwk, enc: 'A128GCM' }
const invalidCredentialRequest = expect.objectContaining({
  errorResponse: expect.objectContaining({ error: 'invalid_credential_request' }),
})
const invalidEncryptionParameters = expect.objectContaining({
  errorResponse: expect.objectContaining({ error: 'invalid_encryption_parameters' }),
})

async function encryptRequest(body: unknown, header: Record<string, unknown> = {}) {
  return new jose.CompactEncrypt(new TextEncoder().encode(JSON.stringify(body)))
    .setProtectedHeader({ kid: jwk.kid, alg: jwk.alg, enc: 'A128GCM', ...header })
    .encrypt(publicKey)
}

const decoders = [
  {
    name: 'credential',
    decode: decryptCredentialRequest,
    body: { credential_identifier: 'credential-id' },
    deferred: false,
  },
  {
    name: 'deferred credential',
    decode: decryptCredentialRequest,
    body: { transaction_id: 'transaction-id' },
    deferred: true,
  },
] as const

describe.each(decoders)('$name request decryption', ({ decode, body, deferred }) => {
  const options = (overrides: Partial<DecryptCredentialRequestOptions> = {}): DecryptCredentialRequestOptions => ({
    body,
    issuerMetadata,
    callbacks,
    ...overrides,
  })

  test('decrypts with the advertised key and passes the result to the existing parser', async () => {
    const request = { ...body, credential_response_encryption: responseEncryption }
    const decrypt = vi.fn(decryptJwe)
    const jwe = await encryptRequest(request)
    const result = await decode(options({ body: jwe, callbacks: { decryptJwe: decrypt } }))

    expect(decrypt).toHaveBeenCalledWith(jwe, { jwk })
    expect(result).toEqual(request)
    if (!deferred) {
      expect(
        parseCredentialRequestPayload({ issuerMetadata, credentialRequest: result }).credentialResponseEncryption
      ).toEqual(responseEncryption)
    } else {
      expect(
        parseDeferredCredentialRequestPayload({ issuerMetadata, deferredCredentialRequest: result })
          .deferredCredentialRequest.credential_response_encryption
      ).toEqual(responseEncryption)
    }
  })

  test('rejects an encrypted request without advertised request encryption', async () => {
    const metadata = {
      ...issuerMetadata,
      credentialIssuer: { ...issuerMetadata.credentialIssuer, credential_request_encryption: undefined },
    }
    await expect(decode(options({ issuerMetadata: metadata, body: await encryptRequest(body) }))).rejects.toThrow(
      invalidEncryptionParameters
    )
  })

  test('rejects encrypted requests with zip even when the value is advertised, before decrypting', async () => {
    const metadata = {
      ...issuerMetadata,
      credentialIssuer: {
        ...issuerMetadata.credentialIssuer,
        credential_request_encryption: {
          ...issuerMetadata.credentialIssuer.credential_request_encryption,
          zip_values_supported: ['DEF'],
        },
      },
    }
    const decrypt = vi.fn(decryptJwe)
    await expect(
      decode(
        options({
          issuerMetadata: metadata,
          body: await encryptRequest(body, { zip: 'DEF' }),
          callbacks: { decryptJwe: decrypt },
        })
      )
    ).rejects.toThrow(invalidEncryptionParameters)
    expect(decrypt).not.toHaveBeenCalled()
  })

  test('rejects failed decryption with invalid_encryption_parameters', async () => {
    await expect(
      decode(
        options({
          body: await encryptRequest(body),
          callbacks: { decryptJwe: () => ({ decrypted: false }) },
        })
      )
    ).rejects.toThrow(invalidEncryptionParameters)
  })

  test('rejects a corrupted authentication tag as invalid_encryption_parameters', async () => {
    const parts = (await encryptRequest(body)).split('.')
    const tag = Buffer.from(parts[4], 'base64url')
    tag[0] ^= 1
    parts[4] = tag.toString('base64url')

    await expect(decode(options({ body: parts.join('.') }))).rejects.toThrow(invalidEncryptionParameters)
  })

  test('reports a throwing callback on corrupted ciphertext as server_error', async () => {
    const parts = (await encryptRequest(body)).split('.')
    const tag = Buffer.from(parts[4], 'base64url')
    tag[0] ^= 1
    parts[4] = tag.toString('base64url')

    await expect(
      decode(
        options({
          body: parts.join('.'),
          callbacks: {
            decryptJwe: async (jwe) => {
              const { plaintext } = await jose.compactDecrypt(jwe, privateKey)
              return { decrypted: true, payload: new TextDecoder().decode(plaintext), decryptionJwk: jwk }
            },
          },
        })
      )
    ).rejects.toMatchObject({
      status: 500,
      errorResponse: { error: 'server_error' },
      cause: expect.any(jose.errors.JWEDecryptionFailed),
    })
  })

  test.each([
    new Error('KMS unavailable'),
    new Oauth2ServerErrorResponseError({ error: 'invalid_encryption_parameters' }),
  ])('maps callback failures to server_error while preserving their cause', async (failure) => {
    await expect(
      decode(
        options({
          body: await encryptRequest(body),
          callbacks: {
            decryptJwe: () => {
              throw failure
            },
          },
        })
      )
    ).rejects.toMatchObject({
      status: 500,
      errorResponse: { error: 'server_error' },
      cause: failure,
    })
  })

  test('reports a missing decryption callback as server_error', async () => {
    await expect(decode(options({ body: await encryptRequest(body), callbacks: {} }))).rejects.toMatchObject({
      status: 500,
      errorResponse: { error: 'server_error' },
      message: expect.stringContaining('No decryptJwe callback'),
      cause: undefined,
    })
  })

  test('rejects invalid JSON in decrypted payload', async () => {
    await expect(
      decode(
        options({
          body: await encryptRequest(body),
          callbacks: { decryptJwe: () => ({ decrypted: true, payload: 'invalid JSON', decryptionJwk: jwk }) },
        })
      )
    ).rejects.toThrow(invalidCredentialRequest)
  })

  test.each(['null', '[]'])('passes decrypted JSON to schema validation: %s', async (payload) => {
    await expect(
      decode(
        options({
          body: await encryptRequest(body),
          callbacks: { decryptJwe: () => ({ decrypted: true, payload, decryptionJwk: jwk }) },
        })
      )
    ).resolves.toEqual(JSON.parse(payload))
  })

  test('rejects a non-string encrypted body', async () => {
    await expect(decode(options({ body: {} }))).rejects.toThrow(invalidEncryptionParameters)
  })
})
