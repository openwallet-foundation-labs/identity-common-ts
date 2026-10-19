import type { z } from 'zod'
import { commonMetadataSchema } from '../../common'
import { swapValidators } from '../../operator'
import { metadataPolicySchema } from '../../policy'

export const createEntity = <T extends string, S extends z.ZodRawShape>({
  identifier,
  additionalValidation = {} as S,
}: {
  identifier: T
  additionalValidation?: S
}) => {
  const schema = commonMetadataSchema.extend(additionalValidation)
  return {
    identifier,
    // Metadata parameters the schema does not define are kept, for example the protocol specific parameters of
    // `oauth_authorization_server`. Dropping them would remove them from the resolved metadata.
    schema: schema.loose(),
    policySchema: swapValidators(schema, metadataPolicySchema.optional()),
  }
}
