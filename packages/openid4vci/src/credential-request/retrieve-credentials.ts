import {
  type CallbackContext,
  Oauth2Error,
  type RequestDpopOptions,
  type ResourceRequestResponseNotOk,
  type ResourceRequestResponseOk,
  resourceRequest,
  type zOauth2ErrorResponse,
} from '@openid4vc/oauth2'
import { ContentType, type FetchResponse, isResponseContentType, stringToJsonWithErrorHandling } from '@openid4vc/utils'
import {
  addValidationIssue,
  parseWithErrorHandling,
  parseWithSchema,
  type SchemaParseResult,
  VALIDATION_CODES,
} from '@owf/identity-common'
import type { JweEncryptor } from '@owf/jose'
import type z from 'zod'
import { Openid4vciError } from '../error/Openid4vciError'
import { getKnownCredentialConfigurationSupportedById } from '../metadata/credential-issuer/credential-issuer-metadata'
import type { IssuerMetadataResult } from '../metadata/fetch-issuer-metadata'
import { Openid4vciVersion } from '../version'
import {
  type CredentialRequest,
  type CredentialRequestWithFormats,
  zCredentialRequest,
  zCredentialRequestDraft14To11,
  zDeferredCredentialRequest,
} from './z-credential-request'
import type {
  CredentialRequestProof,
  CredentialRequestProofs,
  CredentialResponseEncryption,
} from './z-credential-request-common'
import {
  type CredentialResponse,
  type DeferredCredentialResponse,
  zCredentialErrorResponse,
  zCredentialResponse,
  zDeferredCredentialResponse,
} from './z-credential-response'

/**
 * Handles credential response by detecting content type, decrypting if needed, and parsing.
 */
async function handleCredentialResponse<T, Schema extends z.ZodType<T>>(options: {
  response: FetchResponse
  decryptJwe: CallbackContext['decryptJwe']
  credentialResponseEncryption?: CredentialResponseEncryption
  schema: Schema
  responseType: string
}): Promise<{ ok: true; data: T } | { ok: false; parseResult: SchemaParseResult<T> | undefined }> {
  const { response, decryptJwe, credentialResponseEncryption, schema, responseType } = options

  // Check if the response is encrypted (Content-Type: application/jwt)
  if (isResponseContentType(ContentType.Jwt, response)) {
    const jwe = await response.clone().text()
    const decryptResult = await decryptJwe(jwe, { jwk: credentialResponseEncryption?.jwk })

    if (!decryptResult.decrypted) {
      return { ok: false, parseResult: undefined }
    }

    const jsonPayload = stringToJsonWithErrorHandling(
      decryptResult.payload,
      `Unable to parse decrypted ${responseType} as JSON`
    )
    const parseResult = parseWithSchema(schema, jsonPayload)

    if (!parseResult.success) {
      return { ok: false, parseResult }
    }

    return { ok: true, data: parseResult.data }
  }

  // If encryption was requested but response is not encrypted, that's an error
  if (credentialResponseEncryption) {
    throw new Openid4vciError(
      `Encryption was requested via 'credential_response_encryption' but the ${responseType} was not encrypted. ` +
        `Expected Content-Type 'application/jwt' but received '${response.headers.get('Content-Type')}'.`
    )
  }

  // Try to parse the response (non-encrypted)
  const parseResult = isResponseContentType(ContentType.Json, response)
    ? parseWithSchema(schema, await response.clone().json())
    : undefined

  if (!parseResult?.success) {
    return { ok: false, parseResult }
  }

  return { ok: true, data: parseResult.data }
}

export interface CredentialRequestEncryption {
  /** kid of the advertised key to use. Defaults to the first advertised key. */
  kid?: string
  /** enc to use. Must be advertised. Defaults to the first supported value. */
  enc?: string
}

interface RetrieveCredentialsBaseOptions {
  /**
   * Metadata of the credential issuer and authorization servers.
   */
  issuerMetadata: IssuerMetadataResult

  /**
   * Callbacks used in retrieve credentials endpoints.
   */
  callbacks: Pick<CallbackContext, 'fetch' | 'generateRandom' | 'hash' | 'signJws' | 'decryptJwe'> &
    Partial<Pick<CallbackContext, 'encryptJwe'>>

  /**
   * Access token authorized to retrieve the credential(s)
   */
  accessToken: string

  /**
   * DPoP options
   */
  dpop?: RequestDpopOptions

  /**
   * Request encryption of the credential response. When provided, the client
   * includes `credential_response_encryption` in the request and expects
   * an encrypted JWE response.
   *
   * The `decryptJwe` callback must be provided to decrypt the response.
   */
  credentialResponseEncryption?: CredentialResponseEncryption

  /**
   * Encrypt the Credential Request, selecting from the issuer's advertised keys and algorithms.
   * Requests are encrypted automatically when the issuer requires encryption or when
   * response-encryption parameters require it for V1 or an issuer advertising request encryption.
   */
  credentialRequestEncryption?: CredentialRequestEncryption
}

export interface RetrieveCredentialsWithCredentialConfigurationIdOptions extends RetrieveCredentialsBaseOptions {
  /**
   * Additional payload to include in the credential request.
   */
  additionalRequestPayload?: Record<string, unknown>

  /**
   * The credential configuration id to request
   */
  credentialConfigurationId: string

  proof?: CredentialRequestProof
  proofs?: CredentialRequestProofs
}

export async function retrieveCredentialsWithCredentialConfigurationId(
  options: RetrieveCredentialsWithCredentialConfigurationIdOptions
) {
  if (
    options.issuerMetadata.originalDraftVersion !== Openid4vciVersion.Draft15 &&
    options.issuerMetadata.originalDraftVersion !== Openid4vciVersion.V1
  ) {
    throw new Openid4vciError(
      'Requesting credentials based on credential configuration ID is not supported in OpenID4VCI below draft 15. Make sure to provide the format and format specific claims in the request.'
    )
  }

  // This ensures the credential configuration exists
  getKnownCredentialConfigurationSupportedById(options.issuerMetadata, options.credentialConfigurationId)

  const credentialRequest: CredentialRequest = {
    ...options.additionalRequestPayload,

    credential_configuration_id: options.credentialConfigurationId,
    proof: options.proof,
    proofs: options.proofs,
    credential_response_encryption: options.credentialResponseEncryption,
  }

  return retrieveCredentials({
    callbacks: options.callbacks,
    credentialRequest,
    issuerMetadata: options.issuerMetadata,
    accessToken: options.accessToken,
    dpop: options.dpop,
    credentialResponseEncryption: options.credentialResponseEncryption,
    credentialRequestEncryption: options.credentialRequestEncryption,
  })
}

export interface RetrieveCredentialsWithFormatOptions extends RetrieveCredentialsBaseOptions {
  /**
   * Additional payload to include in the credential request.
   */
  additionalRequestPayload?: Record<string, unknown>

  /**
   * The format specific payload. Needs to at least include the `format` and other params
   * are determined by the format itself
   */
  formatPayload: CredentialRequestWithFormats

  proof?: CredentialRequestProof
  proofs?: CredentialRequestProofs
}

export async function retrieveCredentialsWithFormat(options: RetrieveCredentialsWithFormatOptions) {
  if (
    options.issuerMetadata.originalDraftVersion === Openid4vciVersion.Draft15 ||
    options.issuerMetadata.originalDraftVersion === Openid4vciVersion.V1
  ) {
    throw new Openid4vciError(
      'Requesting credentials based on format is not supported on OpenID4VCI above draft 15. Provide the credential configuration id directly in the request.'
    )
  }

  const credentialRequest: CredentialRequest = {
    ...options.formatPayload,
    ...options.additionalRequestPayload,

    proof: options.proof,
    proofs: options.proofs,
    credential_response_encryption: options.credentialResponseEncryption,
  }

  return retrieveCredentials({
    callbacks: options.callbacks,
    credentialRequest,
    issuerMetadata: options.issuerMetadata,
    accessToken: options.accessToken,
    dpop: options.dpop,
    credentialResponseEncryption: options.credentialResponseEncryption,
    credentialRequestEncryption: options.credentialRequestEncryption,
  })
}

export interface RetrieveCredentialsOptions extends RetrieveCredentialsBaseOptions {
  /**
   * The credential request
   */
  credentialRequest: CredentialRequest
}

export interface RetrieveCredentialsResponseOk extends ResourceRequestResponseOk {
  /**
   * The successful validated (in structure, not the actual contents are validated) credential response payload
   */
  credentialResponse: CredentialResponse
}

export interface RetrieveCredentialsResponseNotOk extends ResourceRequestResponseNotOk {
  /**
   * If this is defined it means the response itself was successful but the validation of the
   * credential response data structure failed
   */
  credentialResponseResult?: SchemaParseResult<z.output<typeof zCredentialResponse>>

  /**
   * If this is defined it means the response was JSON and we tried to parse it as
   * a credential error response. It may be successful or it may not be.
   */
  credentialErrorResponseResult?: SchemaParseResult<z.output<typeof zCredentialErrorResponse>>
}

/**
 * internal method
 */
async function retrieveCredentials(
  options: RetrieveCredentialsOptions
): Promise<RetrieveCredentialsResponseNotOk | RetrieveCredentialsResponseOk> {
  const credentialEndpoint = options.issuerMetadata.credentialIssuer.credential_endpoint

  let credentialRequest = parseWithErrorHandling(
    zCredentialRequest,
    options.credentialRequest,
    'Error validating credential request'
  )

  if (credentialRequest.proofs) {
    const { batch_credential_issuance } = options.issuerMetadata.credentialIssuer
    if (options.issuerMetadata.originalDraftVersion === Openid4vciVersion.Draft11) {
      throw new Oauth2Error(
        `Credential issuer '${options.issuerMetadata.credentialIssuer.credential_issuer}' does not support batch credential issuance using the 'proofs' request property. Only 'proof' is supported.`
      )
    }

    const proofs = Object.values(credentialRequest.proofs)[0]
    if (proofs.length > (batch_credential_issuance?.batch_size ?? 1)) {
      throw new Oauth2Error(
        `Credential issuer '${options.issuerMetadata.credentialIssuer.credential_issuer}' supports batch issuance, but the max batch size is '${batch_credential_issuance?.batch_size ?? 1}'. A total of '${proofs.length}' proofs were provided.`
      )
    }
  }

  if (options.issuerMetadata.originalDraftVersion === Openid4vciVersion.Draft11) {
    credentialRequest = parseWithErrorHandling(
      zCredentialRequestDraft14To11,
      credentialRequest,
      `Error transforming credential request from ${Openid4vciVersion.Draft14} to ${Openid4vciVersion.Draft11}`
    )
  }

  const encodedRequest = await encodeCredentialRequest({
    credentialRequest,
    callbacks: options.callbacks,
    issuerMetadata: options.issuerMetadata,
    credentialRequestEncryption: options.credentialRequestEncryption,
  })

  const resourceResponse = await resourceRequest({
    dpop: options.dpop,
    accessToken: options.accessToken,
    callbacks: options.callbacks,
    url: credentialEndpoint,
    requestOptions: {
      method: 'POST',
      headers: {
        'Content-Type': encodedRequest.contentType,
      },
      body: encodedRequest.body,
    },
  })

  if (!resourceResponse.ok) {
    const credentialErrorResponseResult = isResponseContentType(ContentType.Json, resourceResponse.response)
      ? parseWithSchema(zCredentialErrorResponse, await resourceResponse.response.clone().json())
      : undefined

    return {
      ...resourceResponse,
      credentialErrorResponseResult,
    }
  }

  const result = await handleCredentialResponse<CredentialResponse, typeof zCredentialResponse>({
    response: resourceResponse.response,
    decryptJwe: options.callbacks.decryptJwe,
    credentialResponseEncryption: options.credentialResponseEncryption,
    schema: zCredentialResponse,
    responseType: 'credential response',
  })

  if (!result.ok) {
    return {
      ...resourceResponse,
      ok: false,
      credentialResponseResult: result.parseResult,
    }
  }

  return {
    ...resourceResponse,
    credentialResponse: result.data,
  }
}

export interface RetrieveDeferredCredentialsOptions extends RetrieveCredentialsBaseOptions {
  /**
   * Additional payload to include in the credential request.
   */
  additionalRequestPayload?: Record<string, unknown>

  /**
   * The transaction ID
   */
  transactionId: string
}

export interface RetrieveDeferredCredentialsResponseOk extends ResourceRequestResponseOk {
  /**
   * The successful validated (in structure, not the actual contents are validated) deferred credential response payload
   */
  deferredCredentialResponse: DeferredCredentialResponse
}

export interface RetrieveDeferredCredentialsResponseNotOk extends ResourceRequestResponseNotOk {
  /**
   * If this is defined it means the response itself was successful but the validation of the
   * credential response data structure failed
   */
  deferredCredentialResponseResult?: SchemaParseResult<z.output<typeof zDeferredCredentialResponse>>

  /**
   * If this is defined it means the response was JSON and we tried to parse it as
   * a credential error response. It may be successful or it may not be.
   */
  deferredCredentialErrorResponseResult?: SchemaParseResult<z.output<typeof zOauth2ErrorResponse>>
}

export async function retrieveDeferredCredentials(
  options: RetrieveDeferredCredentialsOptions
): Promise<RetrieveDeferredCredentialsResponseNotOk | RetrieveDeferredCredentialsResponseOk> {
  const credentialEndpoint = options.issuerMetadata.credentialIssuer.deferred_credential_endpoint
  if (!credentialEndpoint) {
    throw new Openid4vciError(
      `Credential issuer '${options.issuerMetadata.credentialIssuer.credential_issuer}' does not support deferred credential retrieval.`
    )
  }

  const deferredCredentialRequest = parseWithErrorHandling(
    zDeferredCredentialRequest,
    {
      transaction_id: options.transactionId,
      credential_response_encryption: options.credentialResponseEncryption,
      ...options.additionalRequestPayload,
    },
    'Error validating deferred credential request'
  )

  const encodedRequest = await encodeCredentialRequest({
    credentialRequest: deferredCredentialRequest,
    callbacks: options.callbacks,
    issuerMetadata: options.issuerMetadata,
    credentialRequestEncryption: options.credentialRequestEncryption,
  })

  const resourceResponse = await resourceRequest({
    dpop: options.dpop,
    accessToken: options.accessToken,
    callbacks: options.callbacks,
    url: credentialEndpoint,
    requestOptions: {
      method: 'POST',
      headers: {
        'Content-Type': encodedRequest.contentType,
      },
      body: encodedRequest.body,
    },
  })

  if (!resourceResponse.ok) {
    const deferredCredentialErrorResponseResult = isResponseContentType(ContentType.Json, resourceResponse.response)
      ? parseWithSchema(zCredentialErrorResponse, await resourceResponse.response.clone().json())
      : undefined

    return {
      ...resourceResponse,
      deferredCredentialErrorResponseResult,
    }
  }

  const zDeferredResponse = zDeferredCredentialResponse.superRefine((response, ctx) => {
    if (response.credentials || response.transaction_id === options.transactionId) return
    addValidationIssue(ctx, {
      code: VALIDATION_CODES.CLAIM_VALUE_MISMATCH,
      path: ['transaction_id'],
      message: `Transaction id in deferred credential response does not match transaction id in deferred credential request '${options.transactionId}'`,
      context: { expected: [options.transactionId], actual: response.transaction_id },
    })
  })

  const result = await handleCredentialResponse<DeferredCredentialResponse, typeof zDeferredResponse>({
    response: resourceResponse.response,
    decryptJwe: options.callbacks.decryptJwe,
    credentialResponseEncryption: options.credentialResponseEncryption,
    schema: zDeferredResponse,
    responseType: 'deferred credential response',
  })

  if (!result.ok) {
    return {
      ...resourceResponse,
      ok: false,
      deferredCredentialResponseResult: result.parseResult,
    }
  }

  return {
    ...resourceResponse,
    deferredCredentialResponse: result.data,
  }
}

/**
 * OpenID4VCI 1.0 §10 requires the `alg` inside the response encryption `jwk`, while draft 14/15 require it next
 * to the `jwk`, so the `alg` is placed where the issuer's version expects it.
 */
function withCredentialResponseEncryptionAlg(
  credentialResponseEncryption: CredentialResponseEncryption,
  version: Openid4vciVersion
): CredentialResponseEncryption {
  const alg = credentialResponseEncryption.jwk.alg ?? credentialResponseEncryption.alg
  if (!alg) {
    throw new Openid4vciError(`The 'jwk' in 'credentialResponseEncryption' is missing the required 'alg' parameter.`)
  }

  return version === Openid4vciVersion.V1
    ? { ...credentialResponseEncryption, jwk: { ...credentialResponseEncryption.jwk, alg } }
    : { ...credentialResponseEncryption, alg }
}

async function encodeCredentialRequest(options: {
  credentialRequest: Record<string, unknown>
  callbacks: RetrieveCredentialsBaseOptions['callbacks']
  issuerMetadata: IssuerMetadataResult
  credentialRequestEncryption?: CredentialRequestEncryption
}): Promise<{ contentType: ContentType; body: string }> {
  const supported = options.issuerMetadata.credentialIssuer.credential_request_encryption
  const responseEncryptionRequested = options.credentialRequest.credential_response_encryption !== undefined
  const responseEncryptionRequired =
    options.issuerMetadata.credentialIssuer.credential_response_encryption?.encryption_required === true
  const responseEncryptionRequirementApplies = options.issuerMetadata.originalDraftVersion !== Openid4vciVersion.Draft11

  if (responseEncryptionRequired && responseEncryptionRequirementApplies && !responseEncryptionRequested) {
    throw new Openid4vciError(
      'The credential issuer requires credential response encryption, but no credentialResponseEncryption was provided.'
    )
  }

  const credentialRequest =
    responseEncryptionRequested && responseEncryptionRequirementApplies
      ? {
          ...options.credentialRequest,
          credential_response_encryption: withCredentialResponseEncryptionAlg(
            options.credentialRequest.credential_response_encryption as CredentialResponseEncryption,
            options.issuerMetadata.originalDraftVersion
          ),
        }
      : options.credentialRequest

  const issuerRequiresEncryption = supported?.encryption_required === true
  const responseEncryptionRequiresEncryptedRequest =
    responseEncryptionRequested &&
    (supported !== undefined || options.issuerMetadata.originalDraftVersion === Openid4vciVersion.V1)
  const shouldEncrypt =
    issuerRequiresEncryption ||
    responseEncryptionRequiresEncryptedRequest ||
    options.credentialRequestEncryption !== undefined

  if (!shouldEncrypt) {
    return {
      contentType: ContentType.Json,
      body: JSON.stringify(credentialRequest),
    }
  }

  if (!supported) {
    throw new Openid4vciError(
      responseEncryptionRequiresEncryptedRequest
        ? 'Credential response encryption cannot be requested because the issuer does not support credential request encryption.'
        : 'Credential request encryption configured, but the issuer does not support credential request encryption.'
    )
  }

  const encryptJwe = options.callbacks.encryptJwe
  if (!encryptJwe) {
    const reason = issuerRequiresEncryption
      ? 'Credential request encryption is required by the issuer'
      : responseEncryptionRequiresEncryptedRequest
        ? 'Credential request encryption is required for credential response encryption'
        : 'Credential request encryption is configured'
    throw new Openid4vciError(`${reason}, but no encryptJwe callback was provided.`)
  }

  const keyId = options.credentialRequestEncryption?.kid
  const key = keyId ? supported.jwks.keys.find((key) => key.kid === keyId) : undefined
  let jwk: (typeof supported.jwks.keys)[number] | undefined
  if (keyId) {
    if (key?.use === undefined || key.use === 'enc') {
      jwk = key
    }
  } else {
    jwk = supported.jwks.keys.find((key) => key.use === undefined || key.use === 'enc')
  }

  if (!jwk) {
    throw new Openid4vciError(
      keyId
        ? !key
          ? `Credential request encryption key with kid '${keyId}' is not advertised by the issuer.`
          : `Credential request encryption key with kid '${keyId}' is not intended for encryption.`
        : 'The issuer does not advertise a key for credential request encryption.'
    )
  }

  const enc = options.credentialRequestEncryption?.enc ?? supported.enc_values_supported[0]
  if (!supported.enc_values_supported.includes(enc)) {
    throw new Openid4vciError(
      `Credential request encryption 'enc' must be one of ${supported.enc_values_supported.map((value) => `'${value}'`).join(', ')}.`
    )
  }

  const encryptor: JweEncryptor = {
    method: 'jwk',
    publicJwk: jwk,
    alg: jwk.alg,
    kid: jwk.kid,
    enc,
  }
  const { jwe } = await encryptJwe(encryptor, JSON.stringify(credentialRequest))

  return {
    contentType: ContentType.Jwt,
    body: jwe,
  }
}
