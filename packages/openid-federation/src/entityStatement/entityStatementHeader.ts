import { z } from 'zod'

/**
 *
 * @todo define extact scheme
 *
 */
export const entityStatementHeaderSchema = z
  .object({
    kid: z.string(),
    typ: z.literal('entity-statement+jwt'),
  })
  .loose()

export type EntityStatementHeaderOptions = z.input<typeof entityStatementHeaderSchema>

export type EntityStatementHeader = z.output<typeof entityStatementHeaderSchema>
