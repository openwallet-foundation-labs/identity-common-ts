import type { FetchLimits } from '@owf/identity-common'
import { type EntityConfigurationClaims, fetchEntityConfiguration } from '../entityConfiguration'
import { OpenidFederationError } from '../error/OpenidFederationError'
import { PolicyErrorStage } from '../error/PolicyErrorStage'
import { verifyJwtSignature } from '../jsonWeb/verifyJsonWebToken'
import { type FetchCallback, fetcher, isSameEntityId, type VerifyCallback } from '../utils'
import { validate } from '../utils/validate'
import { zEntityStatementJwt } from './entityStatementJwt'

export type FetchEntityStatementOptions = {
  iss: string
  sub: string
  verifyJwtCallback: VerifyCallback
  fetchCallback?: FetchCallback
  /** The maximum sizes of the responses, 10 MiB by default (see `FetchLimits` of `@owf/identity-common`) */
  fetchLimits?: FetchLimits
  /**
   *
   * The issuers entity configuration
   *
   * If this is not passed in, it will be fetched from the provided `iss` argument.
   *
   */
  issEntityConfiguration?: EntityConfigurationClaims
  /**
   *
   * Fetch endpoint to get the statements from.
   *
   * If this is not passed in, it will be fetched from the `entityConfiguration.source_endpoint`
   *
   */
  endpoint?: string
}

export const fetchEntityStatement = async ({
  sub,
  verifyJwtCallback,
  iss,
  endpoint,
  issEntityConfiguration,
  fetchCallback,
  fetchLimits,
}: FetchEntityStatementOptions) => {
  const issEntityConfigurationClaims =
    issEntityConfiguration ??
    (await fetchEntityConfiguration({ entityId: iss, verifyJwtCallback, fetchCallback, fetchLimits }))

  const fetchEndpoint = endpoint ?? issEntityConfigurationClaims.metadata?.federation_entity?.federation_fetch_endpoint

  if (!fetchEndpoint) {
    throw new Error('No fetch endpoint provided or in the issuer configuration')
  }

  const entityStatementJwt = await fetcher.get({
    type: 'entityStatement',
    url: fetchEndpoint,
    searchParams: { sub },
    requiredContentType: 'application/entity-statement+jwt',
    fetchCallback,
    fetchLimits,
  })

  // Parse the JWT into its claims and header claims
  const { claims } = validate({
    schema: zEntityStatementJwt,
    data: entityStatementJwt,
    errorMessage: 'fetched entity statement JWT is invalid',
  })

  if (!isSameEntityId(claims.iss, iss) || !isSameEntityId(claims.sub, sub)) {
    throw new OpenidFederationError(
      PolicyErrorStage.Validation,
      `entity statement fetched for issuer '${iss}' and subject '${sub}' has issuer '${claims.iss}' and subject '${claims.sub}'`
    )
  }

  await verifyJwtSignature({
    verifyJwtCallback,
    jwt: entityStatementJwt,
    jwks: issEntityConfigurationClaims.jwks,
  })

  return claims
}
