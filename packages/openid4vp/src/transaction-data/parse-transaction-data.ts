import { Oauth2ErrorCodes, Oauth2ServerErrorResponseError } from '@openid4vc/oauth2'
import { parseIfJson } from '@openid4vc/utils'
import { base64, bytesToString, parseWithSchema, validationErrorMessage } from '@owf/identity-common'
import { type TransactionDataEntry, zTransactionData } from './z-transaction-data'

export interface ParseTransactionDataOptions {
  transactionData: string[]
}

export interface ParsedTransactionDataEntry {
  transactionData: TransactionDataEntry
  transactionDataIndex: number
  encoded: string
}

export function parseTransactionData(options: ParseTransactionDataOptions): ParsedTransactionDataEntry[] {
  const { transactionData } = options

  const decoded = transactionData.map((tdEntry, index) => {
    try {
      // OpenID4VP 1.0 Section 5.1 requires base64url, but padded and standard base64 are accepted as before
      const bytes = base64.decode(tdEntry.replace(/-/g, '+').replace(/_/g, '/'))
      return parseIfJson(bytesToString(bytes, { fatal: true }))
    } catch (error) {
      throw new Oauth2ServerErrorResponseError(
        {
          error: Oauth2ErrorCodes.InvalidTransactionData,
          error_description: `Transaction data entry with index ${index} is not base64url encoded UTF-8.`,
        },
        { cause: error }
      )
    }
  })

  const parsedResult = parseWithSchema(zTransactionData, decoded)
  if (!parsedResult.success) {
    throw new Oauth2ServerErrorResponseError({
      error: Oauth2ErrorCodes.InvalidTransactionData,
      error_description: validationErrorMessage('Failed to parse transaction data.', parsedResult.issues),
    })
  }

  return parsedResult.data.map((decoded, index) => ({
    transactionData: decoded,
    encoded: transactionData[index],
    transactionDataIndex: index,
  }))
}
