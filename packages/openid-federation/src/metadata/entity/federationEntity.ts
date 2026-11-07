import type { z } from 'zod'
import { zHttpsUrl } from '../../utils'
import { createEntity } from './utils'

/**
 *
 * {@link https://openid.net/specs/openid-federation-1_0.html#section-5.1.1-1 | Federation Entity}
 *
 */
export const federationEntityMetadata = createEntity({
  identifier: 'federation_entity',
  additionalValidation: {
    federation_fetch_endpoint: zHttpsUrl.optional(),
    federation_list_endpoint: zHttpsUrl.optional(),
    federation_resolve_endpoint: zHttpsUrl.optional(),
    federation_trust_mark_status_endpoint: zHttpsUrl.optional(),
    federation_trust_mark_list_endpoint: zHttpsUrl.optional(),
    federation_trust_mark_endpoint: zHttpsUrl.optional(),
    federation_historical_keys_endpoint: zHttpsUrl.optional(),
  },
})

export type FederationEntityMetadata = z.input<(typeof federationEntityMetadata)['schema']>
