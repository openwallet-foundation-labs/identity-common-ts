import type { z } from 'zod'
import { zEntityStatementClaims } from '../entityStatement'

export const zEntityConfigurationClaims = zEntityStatementClaims.refine((data) => data.iss === data.sub, {
  message: 'iss and sub must be equal',
  path: ['iss', 'sub'],
})

export type EntityConfigurationClaimsOptions = z.input<typeof zEntityConfigurationClaims>

export type EntityConfigurationClaims = z.output<typeof zEntityConfigurationClaims>
