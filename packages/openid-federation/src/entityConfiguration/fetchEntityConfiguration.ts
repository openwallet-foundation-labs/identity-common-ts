import { OpenidFederationError } from '../error/OpenidFederationError'
import { PolicyErrorStage } from '../error/PolicyErrorStage'
import { verifyJwtSignature } from '../jsonWeb/verifyJsonWebToken'
import { addPaths, type FetchCallback, fetcher, isSameEntityId, type VerifyCallback, zHttpsUrl } from '../utils'
import { validate } from '../utils/validate'
import { zEntityConfigurationJwt } from './entityConfigurationJwt'

export type FetchEntityConfigurationOptions = {
  entityId: string
  verifyJwtCallback: VerifyCallback
  fetchCallback?: FetchCallback
}

/**
 *
 * {@link https://openid.net/specs/openid-federation-1_0.html#section-9.1 | Federation Entity Request}
 *
 */
export const fetchEntityConfiguration = async ({
  entityId,
  verifyJwtCallback,
  fetchCallback,
}: FetchEntityConfigurationOptions) => {
  validate({ schema: zHttpsUrl, data: entityId, errorMessage: `entity id '${entityId}' is not an https URL` })

  // Create the entity URL
  const federationUrl = addPaths(entityId, '.well-known', 'openid-federation')

  // Fetch the JWT entity configuration
  const entityConfigurationJwt = await fetcher.get({
    url: federationUrl,
    requiredContentType: 'application/entity-statement+jwt',
    fetchCallback,
  })

  // Parse the JWT into its claims
  const { claims } = validate({
    schema: zEntityConfigurationJwt,
    data: entityConfigurationJwt,
    errorMessage: 'fetched entity configuration JWT is invalid',
  })

  // The entity configuration must be about the requested entity, otherwise any URL could claim to be another entity
  if (!isSameEntityId(claims.sub, entityId)) {
    throw new OpenidFederationError(
      PolicyErrorStage.Validation,
      `entity configuration fetched for '${entityId}' has subject '${claims.sub}'`
    )
  }

  await verifyJwtSignature({ jwt: entityConfigurationJwt, verifyJwtCallback })

  return claims
}
