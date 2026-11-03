import { zNonEmptyString } from '@owf/identity-common'
import { z } from 'zod'

export const zTransactionEntry = z
  .object({
    type: zNonEmptyString,
    credential_ids: z.tuple([zNonEmptyString], zNonEmptyString),

    // SD-JWT VC specific
    transaction_data_hashes_alg: z.tuple([z.string()], z.string()).optional(),
  })
  .loose()
export type TransactionDataEntry = z.infer<typeof zTransactionEntry>

export const zTransactionData = z.array(zTransactionEntry)
export type TransactionData = z.infer<typeof zTransactionData>
