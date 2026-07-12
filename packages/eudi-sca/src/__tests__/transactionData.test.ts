import { expect, suite, test } from 'vitest'
import { ValueType } from '../credentialMetadata'
import { matchTransactionDataToTransactionDataType, parseTransactionData } from '../transactionData'
import { credential_metadata } from './credentialMetadata.test'

const TRANSACTION_DATA = [
  'eyAgInR5cGUiOiAidXJuOmV1ZGk6c2NhOmNvbS5leGFtcGxlLnBheTp0cmFuc2FjdGlvbjoyIiwgImNyZWRlbnRpYWxfaWRzIjogWyJzY2EiXSwgInBheWxvYWQiOiB7ICJ0cmFuc2FjdGlvbl9pZCI6ICJhYjljNGQ1ZS02Zjc4LTkwMTItMzQ1Ni03ODlhYmNkZWYwMTIiLCAiYW1vdW50IjogIjQ5Ljk5IEVVUiIsICJwYXllZSI6IHsgIm5hbWUiOiAiRXhhbXBsZSBTaG9wIiwgImlkIjogIkRFOThaWlowOTk5OTk5OTk5OSIgfSwgInJld2FyZF9wb2ludHMiOiAiMTUwIiB9IH0',
  'eyAgInR5cGUiOiAidXJuOmV1ZGk6c2NhOmNvbS5leGFtcGxlLnBheTp0cmFuc2FjdGlvbjoxIiwgImNyZWRlbnRpYWxfaWRzIjogWyJzY2EiXSwgInBheWxvYWQiOiB7ICJ0cmFuc2FjdGlvbl9pZCI6ICJhYjljNGQ1ZS02Zjc4LTkwMTItMzQ1Ni03ODlhYmNkZWYwMTIiLCAiYW1vdW50IjogIjQ5Ljk5IEVVUiIsICJwYXllZSI6IHsgIm5hbWUiOiAiRXhhbXBsZSBTaG9wIiwgImlkIjogIkRFOThaWlowOTk5OTk5OTk5OSIgfSB9IH0',
]

suite('transaction data', () => {
  test('parse encoded transaction data', () => {
    const first = parseTransactionData(TRANSACTION_DATA[0])
    const second = parseTransactionData(TRANSACTION_DATA[1])

    expect(first).toMatchObject({
      type: 'urn:eudi:sca:com.example.pay:transaction:2',
      credential_ids: ['sca'],
      payload: {
        transaction_id: 'ab9c4d5e-6f78-9012-3456-789abcdef012',
        amount: '49.99 EUR',
        payee: { name: 'Example Shop', id: 'DE98ZZZ09999999999' },
        reward_points: '150',
      },
    })

    expect(second).toMatchObject({
      type: 'urn:eudi:sca:com.example.pay:transaction:1',
      credential_ids: ['sca'],
      payload: {
        transaction_id: 'ab9c4d5e-6f78-9012-3456-789abcdef012',
        amount: '49.99 EUR',
        payee: { name: 'Example Shop', id: 'DE98ZZZ09999999999' },
      },
    })
  })

  test('match transaction data with credential metadata', () => {
    const parsed = matchTransactionDataToTransactionDataType([TRANSACTION_DATA[0]], credential_metadata)

    expect(parsed).toMatchObject({
      'urn:eudi:sca:com.example.pay:transaction:2': {
        transaction_id: { value: 'ab9c4d5e-6f78-9012-3456-789abcdef012' },
        amount: {
          valueType: 'iso_currency_amount',
          value: '49.99 EUR',
          display: [
            { locale: 'en', name: 'amount' },
            { locale: 'de', name: 'betrag' },
          ],
        },
        name: {
          value: 'Example Shop',
          display: [
            { locale: 'en', name: 'payee' },
            { locale: 'de', name: 'empfänger' },
          ],
        },
        id: { value: 'DE98ZZZ09999999999' },
      },
    })
  })

  test('match transaction data with credential metadata, but type does not exist in transaction data', () => {
    expect(() => matchTransactionDataToTransactionDataType([TRANSACTION_DATA[1]], credential_metadata)).toThrow()
  })

  test('match transaction data with credential metadata, but it contains invalid path', () => {
    const invalidCm = structuredClone(credential_metadata)
    invalidCm.transaction_data_types['urn:eudi:sca:com.example.pay:transaction:2'].claims[0].path = [
      'does',
      'not exist',
    ]
    expect(() => matchTransactionDataToTransactionDataType([TRANSACTION_DATA[0]], invalidCm)).toThrow()
  })

  test('match transaction data with credential metadata, but it contains invalid path but mandatory is not true', () => {
    const invalidCm = structuredClone(credential_metadata)
    invalidCm.transaction_data_types['urn:eudi:sca:com.example.pay:transaction:2'].claims[0].path = [
      'does',
      'not exist',
    ]
    invalidCm.transaction_data_types['urn:eudi:sca:com.example.pay:transaction:2'].claims[0].mandatory = false
    expect(() => matchTransactionDataToTransactionDataType([TRANSACTION_DATA[0]], invalidCm)).not.toThrow()
  })

  test('match transaction data with credential metadata, contains value_type but no display', () => {
    const invalidCm = structuredClone(credential_metadata)
    invalidCm.transaction_data_types['urn:eudi:sca:com.example.pay:transaction:2'].claims[0].value_type = ValueType.Url
    invalidCm.transaction_data_types['urn:eudi:sca:com.example.pay:transaction:2'].claims[0].display = undefined
    expect(() => matchTransactionDataToTransactionDataType([TRANSACTION_DATA[0]], invalidCm)).toThrow()
  })

  test('match transaction data with credential metadata using preferred locale', () => {
    const parsed = matchTransactionDataToTransactionDataType([TRANSACTION_DATA[0]], credential_metadata, 'de')

    expect(parsed).toMatchObject({
      'urn:eudi:sca:com.example.pay:transaction:2': {
        transaction_id: { value: 'ab9c4d5e-6f78-9012-3456-789abcdef012' },
        amount: {
          valueType: 'iso_currency_amount',
          value: '49.99 EUR',
          display: [{ locale: 'de', name: 'betrag' }],
        },
        name: {
          value: 'Example Shop',
          display: [{ locale: 'de', name: 'empfänger' }],
        },
        id: { value: 'DE98ZZZ09999999999' },
      },
    })
  })

  test('match transaction data with credential metadata using non-existent locale', () => {
    const parsed = matchTransactionDataToTransactionDataType([TRANSACTION_DATA[0]], credential_metadata, 'fr')

    expect(parsed).toMatchObject({
      'urn:eudi:sca:com.example.pay:transaction:2': {
        transaction_id: { value: 'ab9c4d5e-6f78-9012-3456-789abcdef012' },
        amount: {
          valueType: 'iso_currency_amount',
          value: '49.99 EUR',
          display: [
            { locale: 'en', name: 'amount' },
            { locale: 'de', name: 'betrag' },
          ],
        },
        name: {
          value: 'Example Shop',
          display: [
            { locale: 'en', name: 'payee' },
            { locale: 'de', name: 'empfänger' },
          ],
        },
        id: { value: 'DE98ZZZ09999999999' },
      },
    })
  })
})
