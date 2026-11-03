import { Oauth2ErrorCodes, Oauth2ServerErrorResponseError } from '@openid4vc/oauth2'
import { base64, base64urlEncode, stringToBytes } from '@owf/identity-common'
import { describe, expect, test } from 'vitest'
import { parseTransactionData } from '../../transaction-data/parse-transaction-data.js'

describe('parseTransactionData', () => {
  test('rejects an entry that is not base64url as invalid_transaction_data', () => {
    expect(() => parseTransactionData({ transactionData: ['not base64url!'] })).toThrow(
      expect.objectContaining({
        constructor: Oauth2ServerErrorResponseError,
        errorResponse: {
          error: Oauth2ErrorCodes.InvalidTransactionData,
          error_description: 'Transaction data entry with index 0 is not base64url encoded UTF-8.',
        },
      })
    )
  })

  test('accepts an entry in padded base64url or in standard base64', () => {
    // `~~~` encodes with a `+`, and the entry needs padding
    const entry = { type: 'a~~~', credential_ids: ['id?'] }
    const encoded = base64.encode(stringToBytes(JSON.stringify(entry)))
    expect(encoded).toMatch(/[+/].*=$/)

    for (const transactionData of [encoded, encoded.replace(/\+/g, '-').replace(/\//g, '_')]) {
      expect(parseTransactionData({ transactionData: [transactionData] })).toEqual([
        { transactionData: entry, encoded: transactionData, transactionDataIndex: 0 },
      ])
    }
  })

  test('lists the issues of an entry that does not validate in the error_description', () => {
    const transactionData = base64urlEncode(JSON.stringify({ type: 'qes' }))

    expect(() => parseTransactionData({ transactionData: [transactionData] })).toThrow(
      expect.objectContaining({
        errorResponse: {
          error: Oauth2ErrorCodes.InvalidTransactionData,
          error_description: expect.stringContaining('0.credential_ids: '),
        },
      })
    )
  })
})
