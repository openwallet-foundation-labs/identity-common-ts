import { type CallbackContext, fetchWellKnownMetadata, Oauth2Error } from '@openid4vc/oauth2'
import { ContentType, joinUriParts, URL } from '@openid4vc/utils'
import { IdentityError, parseWithErrorHandling } from '@owf/identity-common'
import { type DecodeJwtResult, decodeJwt, type JwsSignerWithJwk, verifyJwt, zCompactJwt } from '@owf/jose'
import type { CredentialFormatIdentifier } from '../../formats/credential'
import type { Openid4vciVersion } from '../../version'
import type { IssuerMetadataResult } from '../fetch-issuer-metadata'
import {
  allCredentialIssuerMetadataFormatIdentifiers,
  type CredentialConfigurationSupportedWithFormats,
  type CredentialConfigurationsSupported,
  type CredentialConfigurationsSupportedWithFormats,
  type CredentialIssuerMetadata,
  zCredentialConfigurationSupportedWithFormats,
  zCredentialIssuerMetadataWithDraftVersion,
} from './z-credential-issuer-metadata'
import {
  zSignedCredentialIssuerMetadataHeader,
  zSignedCredentialIssuerMetadataPayload,
} from './z-signed-credential-issuer-metadata'

const wellKnownCredentialIssuerSuffix = '.well-known/openid-credential-issuer'

export interface FetchCredentialIssuerMetadataOptions {
  /**
   * Callbacks for fetching the credential issuer metadata. The `verifyJws`
   * callback is required unless `signedMetadata` is `disallowed`.
   */
  callbacks?: Partial<Pick<CallbackContext, 'fetch' | 'verifyJws'>>

  /**
   * Whether the credential issuer metadata must be signed. This is sent as the `Accept` header.
   * - `required`: only accept signed metadata
   * - `preferred`: accept signed and unsigned metadata, asking the issuer for signed metadata first.
   *   Signed metadata that fails verification results in an error, without falling back to unsigned metadata.
   * - `disallowed`: only accept unsigned metadata
   *
   * @default 'preferred' if a `verifyJws` callback is provided, otherwise 'disallowed'
   */
  signedMetadata?: 'required' | 'preferred' | 'disallowed'

  /**
   * Only used for verifying signed issuer metadata. If not provided
   * current time will be used
   */
  now?: Date

  /**
   * Only used for verifying signed issuer metadata. Allowed clock skew in seconds for the `exp`, `nbf`
   * and `iat` checks.
   *
   * @default 30
   */
  allowedSkewInSeconds?: number
}

export interface CredentialIssuerMetadataSigned {
  jwt: DecodeJwtResult<typeof zSignedCredentialIssuerMetadataHeader, typeof zSignedCredentialIssuerMetadataPayload>
  signer: JwsSignerWithJwk
}

export interface FetchCredentialIssuerMetadataReturn {
  /**
   * The credential issuer metadata, optionally transformed to Draft 14+ syntax
   */
  credentialIssuerMetadata: CredentialIssuerMetadata

  /**
   * The original draft version of the credential issuer metadata
   */
  originalDraftVersion: Openid4vciVersion

  /**
   * Metadata about the signed issuer metadata, if the metadata was signed.
   */
  signed?: CredentialIssuerMetadataSigned
}

/**
 * @inheritdoc {@link fetchWellKnownMetadata}
 */
export async function fetchCredentialIssuerMetadata(
  credentialIssuer: string,
  options?: FetchCredentialIssuerMetadataOptions
): Promise<FetchCredentialIssuerMetadataReturn | null> {
  const parsedIssuerUrl = new URL(credentialIssuer)

  const legacyWellKnownMetadataUrl = joinUriParts(credentialIssuer, [wellKnownCredentialIssuerSuffix])
  const wellKnownMetadataUrl = joinUriParts(parsedIssuerUrl.origin, [
    wellKnownCredentialIssuerSuffix,
    parsedIssuerUrl.pathname,
  ])

  const signedMetadata = options?.signedMetadata ?? (options?.callbacks?.verifyJws ? 'preferred' : 'disallowed')
  const acceptedContentTypeBySignedMetadata = {
    required: [ContentType.Jwt],
    preferred: [ContentType.Jwt, ContentType.Json],
    disallowed: [ContentType.Json],
  } satisfies Record<typeof signedMetadata, [ContentType, ...ContentType[]]>

  // The value determines the Accept header, so we only allow the supported values
  if (signedMetadata !== 'required' && signedMetadata !== 'preferred' && signedMetadata !== 'disallowed') {
    throw new Oauth2Error(
      `The 'signedMetadata' option must be one of 'required', 'preferred' or 'disallowed', received '${signedMetadata}'.`
    )
  }

  if (signedMetadata !== 'disallowed' && !options?.callbacks?.verifyJws) {
    throw new Oauth2Error(
      `Signed credential issuer metadata is ${signedMetadata}, but no 'verifyJws' callback provided to fetch credential issuer metadata method.`
    )
  }

  const acceptedContentType: [ContentType, ...ContentType[]] = acceptedContentTypeBySignedMetadata[signedMetadata]

  // Either unsigned metadata or signed JWT
  const zResponse = zCredentialIssuerMetadataWithDraftVersion.or(zCompactJwt)

  let result = null
  let firstError = null
  // The url that served the metadata, for the error messages
  let metadataUrl = wellKnownMetadataUrl

  try {
    result = await fetchWellKnownMetadata(wellKnownMetadataUrl, zResponse, {
      fetch: options?.callbacks?.fetch,
      acceptedContentType,
    })
  } catch (error) {
    // A library error, such as invalid metadata (a `ValidationError`) or an error response, is thrown.
    // `ValidationError` is not an `Openid4vcBaseError`, so `IdentityError` is what covers both.
    if (error instanceof IdentityError) throw error

    // An exception occurs if a CORS-policy blocks the request, i.e. because the URL is invalid due to the legacy path being used
    // The legacy path should still be tried therefore we store the first error to rethrow it later if needed
    firstError = error
  }

  // If the metadata is not available at the new URL, fetch it at the legacy URL
  // The legacy url is the same if no subpath is used by the issuer
  if (!result && legacyWellKnownMetadataUrl !== wellKnownMetadataUrl) {
    metadataUrl = legacyWellKnownMetadataUrl
    try {
      result = await fetchWellKnownMetadata(legacyWellKnownMetadataUrl, zResponse, {
        fetch: options?.callbacks?.fetch,
        acceptedContentType,
      })
    } catch (error) {
      // If the first attempt also errored, rethrow that original error; otherwise rethrow this one
      throw firstError ?? error
    }
  }

  if (!result && firstError) {
    throw firstError
  }

  let issuerMetadataWithVersion: FetchCredentialIssuerMetadataReturn | null = null

  if (typeof result === 'string') {
    // We won't reach this, as we already check this for the signed metadata option.
    // Mainly to make TS happy
    if (!options?.callbacks?.verifyJws) {
      throw new Oauth2Error(
        `Unable to verify signed credential issuer metadata, no 'verifyJws' callback provided to fetch credential issuer metadata method.`
      )
    }
    const decodedJwt = decodeJwt({
      jwt: result,
      headerSchema: zSignedCredentialIssuerMetadataHeader,
      payloadSchema: zSignedCredentialIssuerMetadataPayload,
    })
    const { payload } = decodedJwt

    const verifyResult = await verifyJwt({
      jwt: decodedJwt,
      verifyJwsCallback: options.callbacks.verifyJws,
      now: options.now,
      skewSeconds: options.allowedSkewInSeconds,
      expectedSubject: credentialIssuer,
      errorMessage: `Verification of the signed credential issuer metadata at '${metadataUrl}' failed`,
    })

    const issuerMetadata = parseWithErrorHandling(
      zCredentialIssuerMetadataWithDraftVersion,
      payload,
      'Unable to determine version for signed issuer metadata'
    )

    issuerMetadataWithVersion = {
      ...issuerMetadata,
      signed: {
        signer: verifyResult.signer,
        jwt: decodedJwt,
      },
    }
  } else if (result) {
    issuerMetadataWithVersion = result
  }

  // credential issuer param MUST match
  if (
    issuerMetadataWithVersion &&
    issuerMetadataWithVersion.credentialIssuerMetadata.credential_issuer !== credentialIssuer
  ) {
    throw new Oauth2Error(
      `The 'credential_issuer' parameter '${issuerMetadataWithVersion.credentialIssuerMetadata.credential_issuer}' in the well known credential issuer metadata at '${metadataUrl}' does not match the provided credential issuer '${credentialIssuer}'.`
    )
  }

  return issuerMetadataWithVersion
}

/**
 * Extract credential configuration supported entries where the `format` is known to this
 * library and the configuration validates correctly. Should be ran only after verifying
 * the credential issuer metadata structure, so we can be certain that if the `format`
 * matches the other format specific requirements are also met.
 *
 * Validation is done when resolving issuer metadata, or when calling `createIssuerMetadata`.
 */
export function extractKnownCredentialConfigurationSupportedFormats(
  credentialConfigurationsSupported: CredentialConfigurationsSupported
): CredentialConfigurationsSupportedWithFormats {
  return Object.fromEntries(
    Object.entries(credentialConfigurationsSupported).filter(
      (entry): entry is [string, CredentialConfigurationSupportedWithFormats] => {
        // Type guard to ensure that the returned entries have known formats
        const credentialConfiguration = zCredentialConfigurationSupportedWithFormats.safeParse(entry[1]) // Validate structure
        if (!credentialConfiguration.success) {
          return false
        }
        return allCredentialIssuerMetadataFormatIdentifiers.includes(
          credentialConfiguration.data.format as CredentialFormatIdentifier
        )
      }
    )
  )
}

/**
 * Get a known credential configuration supported by its id, it will throw an error if the configuration
 * is not found or if its found but the credential configuration is invalid.
 */
export function getKnownCredentialConfigurationSupportedById(
  issuerMetadata: IssuerMetadataResult,
  credentialConfigurationId: string
) {
  const configuration = issuerMetadata.credentialIssuer.credential_configurations_supported[credentialConfigurationId]

  if (!configuration) {
    throw new Oauth2Error(
      `Credential configuration with id '${credentialConfigurationId}' not found in credential configurations supported.`
    )
  }

  if (!issuerMetadata.knownCredentialConfigurations[credentialConfigurationId]) {
    parseWithErrorHandling(
      zCredentialConfigurationSupportedWithFormats,
      configuration,
      `Credential configuration with id '${credentialConfigurationId}' is not valid`
    )
  }

  return issuerMetadata.knownCredentialConfigurations[credentialConfigurationId]
}
