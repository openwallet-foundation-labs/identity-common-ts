import { unionParams } from '@owf/identity-common'
import { z } from 'zod'
import { zOpenid4vpAuthorizationRequest } from './z-authorization-request'
import { zOpenid4vpAuthorizationRequestDcApi } from './z-authorization-request-dc-api'
import { zOpenid4vpAuthorizationRequestIae } from './z-authorization-request-iae'

/**
 * An unsigned OpenID4VP authorization request payload, or the payload of a signed request object.
 */
export const zOpenid4vpAuthorizationRequestPayload = z.union(
  [zOpenid4vpAuthorizationRequestDcApi, zOpenid4vpAuthorizationRequestIae, zOpenid4vpAuthorizationRequest],
  unionParams('Invalid OpenID4VP authorization request', [
    'Digital Credentials API',
    'Interactive Authorization Endpoint',
    'other response modes',
  ])
)

export type Openid4vpAuthorizationRequestPayload = z.infer<typeof zOpenid4vpAuthorizationRequestPayload>
