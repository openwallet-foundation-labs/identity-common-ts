import { z } from 'zod'
import {
  federationEntityMetadata,
  oauthAuthorizationServerEntityMetadata,
  oauthClientEntityMetadata,
  oauthResourceEntityMetadata,
  openidProviderEntityMetadata,
  openidRelyingPartyEntityMetadata,
} from './entity'

export const zMetadataPolicy = z.object({
  [federationEntityMetadata.identifier]: federationEntityMetadata.policySchema.optional(),
  [openidRelyingPartyEntityMetadata.identifier]: openidRelyingPartyEntityMetadata.policySchema.optional(),
  [openidProviderEntityMetadata.identifier]: openidProviderEntityMetadata.policySchema.optional(),
  [oauthAuthorizationServerEntityMetadata.identifier]: oauthAuthorizationServerEntityMetadata.policySchema.optional(),
  [oauthClientEntityMetadata.identifier]: oauthClientEntityMetadata.policySchema.optional(),
  [oauthResourceEntityMetadata.identifier]: oauthResourceEntityMetadata.policySchema.optional(),
})

export type MetadataPolicy = z.infer<typeof zMetadataPolicy>
