import { z } from 'zod'

/**
 *
 * @todo define extact scheme
 *
 */
export const zEntityStatementHeader = z
  .object({
    kid: z.string(),
    typ: z.literal('entity-statement+jwt'),
  })
  .loose()

export type EntityStatementHeaderOptions = z.input<typeof zEntityStatementHeader>

export type EntityStatementHeader = z.output<typeof zEntityStatementHeader>
