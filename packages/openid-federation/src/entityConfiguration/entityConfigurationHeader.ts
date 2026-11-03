import { z } from 'zod'

/**
 *
 * @todo define exact scheme
 *
 */
export const zEntityConfigurationHeader = z
  .object({
    kid: z.string(),
    typ: z.literal('entity-statement+jwt'),
  })
  .loose()

export type EntityConfigurationHeaderOptions = z.input<typeof zEntityConfigurationHeader>

export type EntityConfigurationHeader = z.output<typeof zEntityConfigurationHeader>
