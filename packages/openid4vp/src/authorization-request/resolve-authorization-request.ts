import { type CallbackContext, Oauth2Error, Oauth2ErrorCodes, Oauth2ServerErrorResponseError } from '@openid4vc/oauth2'
import { parseWithErrorHandling } from '@openid4vc/utils'
import z from 'zod'
import {
  type ParsedClientIdentifier,
  validateOpenid4vpClientId,
} from '../client-identifier-prefix/parse-client-identifier-prefix'
import { fetchClientMetadata } from '../fetch-client-metadata'
import { type VerifiedJarRequest, verifyJarRequest } from '../jar/handle-jar-request/verify-jar-request'
import {
  isJarAuthorizationRequest,
  type Openid4vpJarAuthorizationRequest,
  zOpenid4vpJarAuthorizationRequest,
} from '../jar/z-jar-authorization-request'
import type { PexPresentationDefinition } from '../models/z-pex'
import { type ParsedTransactionDataEntry, parseTransactionData } from '../transaction-data/parse-transaction-data'
import { type Openid4vpVersionNumber, parseAuthorizationRequestVersion } from '../version'
import { Openid4vpAuthorizationRequestError } from './Openid4vpAuthorizationRequestError'
import {
  validateOpenid4vpAuthorizationRequestPayload,
  type WalletVerificationOptions,
} from './validate-authorization-request'
import { validateOpenid4vpAuthorizationRequestDcApiPayload } from './validate-authorization-request-dc-api'
import { validateOpenid4vpAuthorizationRequestIaePayload } from './validate-authorization-request-iae'
import { isOpenid4vpAuthorizationRequestDcApi } from './z-authorization-request-dc-api'
import { isOpenid4vpAuthorizationRequestIae } from './z-authorization-request-iae'
import {
  type Openid4vpAuthorizationRequestPayload,
  zOpenid4vpAuthorizationRequestPayload,
} from './z-authorization-request-payload'

export interface ResolveOpenid4vpAuthorizationRequestOptions {
  authorizationRequestPayload: Openid4vpAuthorizationRequestPayload | Openid4vpJarAuthorizationRequest
  wallet?: WalletVerificationOptions

  /**
   * The response mode that is expected for the resolved presentation request.
   */
  responseMode: ExpectedResponseMode

  callbacks: Pick<CallbackContext, 'verifyJwt' | 'decryptJwe' | 'getX509CertificateMetadata' | 'fetch' | 'hash'>
}

export type ResolvedOpenid4vpAuthorizationRequest = {
  transactionData?: ParsedTransactionDataEntry[]
  authorizationRequestPayload: Openid4vpAuthorizationRequestPayload
  jar: VerifiedJarRequest | undefined
  client: ParsedClientIdentifier
  pex?: {
    presentation_definition?: PexPresentationDefinition
    presentation_definition_uri?: string
  }
  dcql?: { query: unknown } | undefined

  /**
   * The highest possible version number based on (draft)-version checks done on the request.
   *
   * 100 means 1.0 final, all other numbers are draft versions.
   */
  version: Openid4vpVersionNumber
}

export async function resolveOpenid4vpAuthorizationRequest(
  options: ResolveOpenid4vpAuthorizationRequestOptions
): Promise<ResolvedOpenid4vpAuthorizationRequest> {
  const { wallet, callbacks } = options

  const parsed = parseWithErrorHandling(
    z.union([zOpenid4vpAuthorizationRequestPayload, zOpenid4vpJarAuthorizationRequest]),
    options.authorizationRequestPayload,
    'Invalid authorization request. Could not parse openid4vp authorization request as openid4vp or jar auth request.'
  )

  let jar: VerifiedJarRequest | undefined
  let authorizationRequestPayload: Openid4vpAuthorizationRequestPayload
  if (isJarAuthorizationRequest(parsed)) {
    jar = await verifyJarRequest({
      jarRequestParams: parsed,
      callbacks,
      wallet,
      // For IAE/DC API only request is allowed
      allowRequestUri: options.responseMode.type === 'direct_post',
    })

    authorizationRequestPayload = parseWithErrorHandling(
      zOpenid4vpAuthorizationRequestPayload,
      jar.authorizationRequestPayload,
      'Invalid authorization request. Could not parse jar request payload as openid4vp auth request.'
    )
  } else {
    authorizationRequestPayload = parsed
  }

  const validateClient = async () => {
    const version = parseAuthorizationRequestVersion(authorizationRequestPayload)
    let clientMetadata = authorizationRequestPayload.client_metadata
    if (
      !isOpenid4vpAuthorizationRequestDcApi(authorizationRequestPayload) &&
      !isOpenid4vpAuthorizationRequestIae(authorizationRequestPayload) &&
      !clientMetadata &&
      authorizationRequestPayload.client_metadata_uri
    ) {
      clientMetadata = await fetchClientMetadata({ clientMetadataUri: authorizationRequestPayload.client_metadata_uri })
    }

    const client = await validateOpenid4vpClientId({
      authorizationRequestPayload: {
        ...authorizationRequestPayload,
        client_metadata: clientMetadata,
      },
      jar,

      callbacks,
      origin: options.responseMode.type === 'dc_api' ? options.responseMode.expectedOrigin : undefined,
      version,
    })

    return { version, client }
  }

  let payloadValidationError: Oauth2ServerErrorResponseError | undefined
  try {
    validateOpenId4vpAuthorizationRequestPayload({
      authorizationRequestPayload,
      wallet,
      jar: jar !== undefined,
      responseMode: options.responseMode,
    })
  } catch (error) {
    if (!(error instanceof Oauth2ServerErrorResponseError)) throw error
    payloadValidationError = error
  }

  const { version, client } = await validateClient().catch((error) => {
    // The payload validation error takes precedence, as the payload is validated first
    const requestError = payloadValidationError ?? error
    if (!(requestError instanceof Oauth2ServerErrorResponseError)) throw requestError

    // Without `client`, as the client is not authenticated
    throw new Openid4vpAuthorizationRequestError(requestError, { authorizationRequestPayload, jar })
  })

  if (payloadValidationError) {
    throw new Openid4vpAuthorizationRequestError(payloadValidationError, { authorizationRequestPayload, client, jar })
  }

  try {
    let pex: ResolvedOpenid4vpAuthorizationRequest['pex'] | undefined
    let dcql: ResolvedOpenid4vpAuthorizationRequest['dcql'] | undefined

    if (
      'presentation_definition_uri' in authorizationRequestPayload &&
      authorizationRequestPayload.presentation_definition_uri
    ) {
      throw new Oauth2ServerErrorResponseError({
        error: Oauth2ErrorCodes.InvalidRequest,
        error_description: 'Cannot fetch presentation definition from URI. Not supported.',
      })
    }

    if (
      'presentation_definition' in authorizationRequestPayload &&
      authorizationRequestPayload.presentation_definition
    ) {
      pex = { presentation_definition: authorizationRequestPayload.presentation_definition }
    }

    if (authorizationRequestPayload.dcql_query) {
      dcql = { query: authorizationRequestPayload.dcql_query }
    }

    const transactionData = authorizationRequestPayload.transaction_data
      ? parseTransactionData({ transactionData: authorizationRequestPayload.transaction_data })
      : undefined

    return {
      transactionData,
      authorizationRequestPayload,
      jar,
      client,
      pex,
      dcql,
      version,
    }
  } catch (error) {
    if (error instanceof Oauth2ServerErrorResponseError) {
      throw new Openid4vpAuthorizationRequestError(error, { authorizationRequestPayload, client, jar })
    }
    throw error
  }
}

type ExpectedResponseMode =
  | {
      /**
       * Enforces the response is `iae` or `iae_post`, meaning the presentation
       * is created as part of an issuance session.
       */
      type: 'iae'

      /**
       * The expectedUrl for the IAE session. Must always be provided, but will
       * only be verified if the OpenID4VP request is signed (and thus MUST contain `expected_url`)
       */
      expectedUrl: string
    }
  | {
      /**
       * Enforces the response is `dc_api` or `dc_api.jwt` (including legacy support for `w3c_dc_api` and `w3c_dc_api.jwt`),
       * meaning the presentation will be shared using the Digital Credentials API.
       */
      type: 'dc_api'

      /**
       * The expected origin for the DC API session. Must always be provided, but will
       * only be verified if the OpenID4VP request is signed (and thus MUST contain `expected_origins`)
       */
      expectedOrigin: string
    }
  | {
      /**
       * Enforces the response is `direct_post` or `direct_post.jwt`
       */
      type: 'direct_post'
    }

function validateOpenId4vpAuthorizationRequestPayload(options: {
  authorizationRequestPayload: Openid4vpAuthorizationRequestPayload
  wallet?: WalletVerificationOptions
  jar: boolean

  responseMode: ExpectedResponseMode
}) {
  const { authorizationRequestPayload, wallet, jar, responseMode } = options

  if (isOpenid4vpAuthorizationRequestDcApi(authorizationRequestPayload)) {
    if (responseMode.type !== 'dc_api') {
      throw new Oauth2Error(
        `Authorization request uses response mode ${authorizationRequestPayload.response_mode}, but expected to use a response mode in the ${responseMode.type} category.`
      )
    }

    validateOpenid4vpAuthorizationRequestDcApiPayload({
      params: authorizationRequestPayload,
      isJarRequest: jar,
      origin: responseMode.expectedOrigin,
    })

    return
  }

  if (isOpenid4vpAuthorizationRequestIae(authorizationRequestPayload)) {
    if (responseMode.type !== 'iae') {
      throw new Oauth2Error(
        `Authorization request uses response mode ${authorizationRequestPayload.response_mode}, but expected to use a response mode in the ${responseMode.type} category.`
      )
    }

    validateOpenid4vpAuthorizationRequestIaePayload({
      params: authorizationRequestPayload,
      isJarRequest: jar,
      expectedUrl: responseMode.expectedUrl,
    })

    return
  }

  if (responseMode.type !== 'direct_post') {
    throw new Oauth2Error(
      `Authorization request uses response mode ${authorizationRequestPayload.response_mode}, but expected to use a response mode in the ${responseMode.type} category.`
    )
  }

  validateOpenid4vpAuthorizationRequestPayload({
    params: authorizationRequestPayload,
    walletVerificationOptions: wallet,
  })
}
