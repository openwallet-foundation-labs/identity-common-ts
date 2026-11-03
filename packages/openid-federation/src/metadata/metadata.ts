import { z } from 'zod'

import {
  federationEntityMetadata,
  oauthAuthorizationServerEntityMetadata,
  oauthClientEntityMetadata,
  oauthResourceEntityMetadata,
  openidCredentialIssuerEntityMetadata,
  openidCredentialVerifierEntityMetadata,
  openidProviderEntityMetadata,
  openidRelyingPartyEntityMetadata,
} from './entity'

export const zMetadata = z
  .object({
    [federationEntityMetadata.identifier]: federationEntityMetadata.schema.optional(),
    [openidRelyingPartyEntityMetadata.identifier]: openidRelyingPartyEntityMetadata.schema.optional(),
    [openidCredentialVerifierEntityMetadata.identifier]: openidCredentialVerifierEntityMetadata.schema.optional(),
    [openidCredentialIssuerEntityMetadata.identifier]: openidCredentialIssuerEntityMetadata.schema.optional(),
    [openidProviderEntityMetadata.identifier]: openidProviderEntityMetadata.schema.optional(),
    [oauthAuthorizationServerEntityMetadata.identifier]: oauthAuthorizationServerEntityMetadata.schema.optional(),
    [oauthClientEntityMetadata.identifier]: oauthClientEntityMetadata.schema.optional(),
    [oauthResourceEntityMetadata.identifier]: oauthResourceEntityMetadata.schema.optional(),
  })
  // Entity types not defined here are kept unvalidated, as OpenID Federation allows further entity types.
  .loose()

export type Metadata = z.input<typeof zMetadata>
