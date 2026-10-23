import crypto from 'node:crypto'
import type { CallbackContext, Jwk } from '@openid4vc/oauth2'
import { ContentType } from '@openid4vc/utils'
import * as jose from 'jose'
import { describe, expect, test, vi } from 'vitest'
import {
  type DecodeCredentialRequestOptions,
  decodeCredentialRequest,
  decodeDeferredCredentialRequest,
} from '../../credential-request/decode-credential-request'
import { parseCredentialRequest } from '../../credential-request/parse-credential-request'
import { parseDeferredCredentialRequest } from '../../credential-request/parse-deferred-credential-request'
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
  const { plaintext } = await jose.compactDecrypt(jwe, privateKey)
  return { decrypted: true, payload: new TextDecoder().decode(plaintext), decryptionJwk: jwk }
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
  { name: 'credential', decode: decodeCredentialRequest, body: { credential_identifier: 'credential-id' } },
  { name: 'deferred credential', decode: decodeDeferredCredentialRequest, body: { transaction_id: 'transaction-id' } },
] as const

describe.each(decoders)('$name request decoding', ({ decode, body }) => {
  const options = (overrides: Partial<DecodeCredentialRequestOptions> = {}): DecodeCredentialRequestOptions => ({
    body,
    contentType: ContentType.Json,
    issuerMetadata,
    callbacks,
    ...overrides,
  })

  test('decrypts with the advertised key and passes the result to the existing parser', async () => {
    const request = { ...body, credential_response_encryption: responseEncryption }
    const decrypt = vi.fn(decryptJwe)
    const jwe = await encryptRequest(request)
    const result = await decode(
      options({ body: jwe, contentType: 'Application/JWT; charset=utf-8', callbacks: { decryptJwe: decrypt } })
    )

    expect(decrypt).toHaveBeenCalledWith(jwe, { jwk })
    expect(result.credentialRequest).toEqual(request)
    if (decode === decodeCredentialRequest) {
      expect(
        parseCredentialRequest({ issuerMetadata, credentialRequest: result.credentialRequest })
          .credentialResponseEncryption
      ).toEqual(responseEncryption)
    } else {
      expect(
        parseDeferredCredentialRequest({ issuerMetadata, deferredCredentialRequest: result.credentialRequest })
          .deferredCredentialRequest.credential_response_encryption
      ).toEqual(responseEncryption)
    }
  })

  test('returns an ordinary plaintext request when encryption is not required', async () => {
    await expect(decode(options())).resolves.toEqual({ credentialRequest: body })
  })

  test('rejects plaintext when issuer metadata requires encryption', async () => {
    const requiredIssuerMetadata = {
      ...issuerMetadata,
      credentialIssuer: {
        ...issuerMetadata.credentialIssuer,
        credential_request_encryption: {
          ...issuerMetadata.credentialIssuer.credential_request_encryption,
          encryption_required: true,
        },
      },
    }
    await expect(decode(options({ issuerMetadata: requiredIssuerMetadata }))).rejects.toThrow(
      invalidEncryptionParameters
    )
  })

  test.each([true, false])(
    'rejects plaintext response-encryption parameters with metadata present: %s',
    async (advertised) => {
      const metadata = advertised
        ? issuerMetadata
        : {
            ...issuerMetadata,
            credentialIssuer: { ...issuerMetadata.credentialIssuer, credential_request_encryption: undefined },
          }
      await expect(
        decode(
          options({ issuerMetadata: metadata, body: { ...body, credential_response_encryption: responseEncryption } })
        )
      ).rejects.toThrow(invalidEncryptionParameters)
    }
  )

  test('rejects an encrypted request without advertised request encryption', async () => {
    const metadata = {
      ...issuerMetadata,
      credentialIssuer: { ...issuerMetadata.credentialIssuer, credential_request_encryption: undefined },
    }
    await expect(
      decode(options({ issuerMetadata: metadata, contentType: ContentType.Jwt, body: await encryptRequest(body) }))
    ).rejects.toThrow(invalidEncryptionParameters)
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
          contentType: ContentType.Jwt,
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
          contentType: ContentType.Jwt,
          callbacks: { decryptJwe: () => ({ decrypted: false }) },
        })
      )
    ).rejects.toThrow(invalidEncryptionParameters)
  })

  test('propagates callback failures unchanged', async () => {
    const failure = new Error('KMS unavailable')
    await expect(
      decode(
        options({
          body: await encryptRequest(body),
          contentType: ContentType.Jwt,
          callbacks: {
            decryptJwe: () => {
              throw failure
            },
          },
        })
      )
    ).rejects.toBe(failure)
  })

  test.each(['invalid JSON', 'null', '[]'])('rejects decrypted non-object payload: %s', async (payload) => {
    await expect(
      decode(
        options({
          body: await encryptRequest(body),
          contentType: ContentType.Jwt,
          callbacks: { decryptJwe: () => ({ decrypted: true, payload, decryptionJwk: jwk }) },
        })
      )
    ).rejects.toThrow(invalidCredentialRequest)
  })

  test.each([null, [], 'not JSON', 123])('rejects a non-object plaintext body: %s', async (value) => {
    await expect(decode(options({ body: value }))).rejects.toThrow(invalidCredentialRequest)
  })

  test.each([undefined, 'text/plain', 'application/jsonp', 'application/jwt, application/json'])(
    'rejects unsupported Content-Type: %s',
    async (contentType) => {
      await expect(decode(options({ contentType }))).rejects.toThrow(invalidCredentialRequest)
    }
  )

  test('rejects a non-string encrypted body', async () => {
    await expect(decode(options({ contentType: ContentType.Jwt }))).rejects.toThrow(invalidEncryptionParameters)
  })
})
