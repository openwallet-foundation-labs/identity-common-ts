import { base64url, bytesToString } from '@owf/identity-common'
import z from 'zod'
import {
  type CredentialMetadata,
  type CredentialMetadataDisplay,
  parseCredentialMetadata,
  ValueType,
} from './credentialMetadata'
import { getJsonPathValueAndKey, Iso4217Amount, Iso4217CurrencyCode } from './utils'

export const TRANSACTION_DATA_SCA_PREFIX = 'urn:eudi:sca:'

const TransactionDataSchema = z.object({
  type: z.string(),
  credential_ids: z.array(z.string()),
  transaction_hash_alg: z.string().optional(),
  payload: z.record(z.string(), z.unknown()),
})

export type TransactionData = z.infer<typeof TransactionDataSchema>

export const parseTransactionData = (txnData: string) => {
  const decoded = JSON.parse(bytesToString(base64url.decode(txnData)))
  return TransactionDataSchema.parse(decoded)
}

export type PayloadWithDisplayInfo = Record<
  string,
  {
    value: unknown
    valueType?: string
    display?: CredentialMetadataDisplay
  }
>

const __matchTransactionDataToTransactionDataType = (
  transactionData: Array<TransactionData>,
  credentialMetadata: CredentialMetadata,
  preferredLocale?: string
): Record<string, PayloadWithDisplayInfo> => {
  const transactionDataTypes = Object.entries(credentialMetadata.transaction_data_types).reduce<
    CredentialMetadata['transaction_data_types']
  >((prev, [key, value]) => {
    if (key.startsWith(TRANSACTION_DATA_SCA_PREFIX)) {
      prev[key] = value
    }
    return prev
  }, {})

  if (Object.keys(transactionData).length === 0) {
    throw new Error(`No transaction data found with the required prefix of '${TRANSACTION_DATA_SCA_PREFIX}'`)
  }

  return transactionData.reduce<Record<string, PayloadWithDisplayInfo>>((prev, td) => {
    const transactionDataType = transactionDataTypes[td.type]
    if (!transactionDataType) {
      throw new Error(`Could not find transaction data type in credential metadata for key '${td.type}'`)
    }

    const claims = transactionDataType.claims.reduce<PayloadWithDisplayInfo>(
      (prev, { path, mandatory, value_type, display }) => {
        const jsonPathValueAndKey = getJsonPathValueAndKey(path, td.payload)
        if (!jsonPathValueAndKey) return prev
        if (value_type && value_type === ValueType.LabelOnly && mandatory) return prev
        const doesValueTypeMatch = value_type ? matchValueTypeToValue(value_type, jsonPathValueAndKey.value) : true
        const isValid = !!jsonPathValueAndKey && doesValueTypeMatch
        const shouldBeAdded = mandatory ? mandatory === isValid : isValid

        if (shouldBeAdded) {
          const preferredDisplay = preferredLocale
            ? display?.find(({ locale }) => locale === preferredLocale)
            : undefined

          prev[jsonPathValueAndKey.key] = {
            valueType: value_type,
            value: jsonPathValueAndKey.value,
            display: preferredDisplay ? [preferredDisplay] : display,
          }
        }
        return prev
      },
      {}
    )

    const doClaimsPathMatchPayload = transactionDataType.claims
      .filter(({ mandatory }) => mandatory)
      .every(({ path, value_type }) => {
        if (value_type && value_type === ValueType.LabelOnly) return true
        const jsonPathValueAndKey = getJsonPathValueAndKey(path, td.payload)
        if (!jsonPathValueAndKey) return false
        return value_type ? matchValueTypeToValue(value_type, jsonPathValueAndKey.value) : true
      })

    if (!doClaimsPathMatchPayload) {
      const invalidClaims = transactionDataType.claims.filter(({ path, mandatory, value_type }) => {
        if (!mandatory) return false
        const jsonPathValueAndKey = getJsonPathValueAndKey(path, td.payload)
        if (!jsonPathValueAndKey) return true
        if (value_type && value_type === ValueType.LabelOnly) return true
        const doesValueTypeMatch = value_type ? matchValueTypeToValue(value_type, jsonPathValueAndKey.value) : true
        return !doesValueTypeMatch
      })
      throw new Error(
        `Credential is not compatible. Missing paths: [${invalidClaims
          .map(({ path }) => `[${path.join(', ')}]`)
          .join(', ')}]`
      )
    }

    prev[td.type] = claims

    return prev
  }, {})
}

export const matchTransactionDataToTransactionDataType = (
  transactionData: Array<string>,
  credentialMetadata: Record<string, unknown>,
  preferredLocale?: string
) => {
  const parsedTransactionData = transactionData
    .map((td) => {
      try {
        return parseTransactionData(td)
      } catch {
        return undefined
      }
    })
    .filter((td) => td !== undefined)
  const parsedCredentialMetadata = parseCredentialMetadata(credentialMetadata)
  return __matchTransactionDataToTransactionDataType(parsedTransactionData, parsedCredentialMetadata, preferredLocale)
}

const matchValueTypeToValue = (valueType: ValueType | string, value: unknown) => {
  switch (valueType) {
    case ValueType.Boolean:
      return typeof value === 'boolean'
    case ValueType.Frequency:
      return (
        typeof value === 'string' &&
        ['INDA', 'DAIL', 'WEEK', 'TOWK', 'TWMN', 'MNTH', 'TOMN', 'QUTR', 'FOMN', 'SEMI', 'YEAR', 'TYEA'].includes(value)
      )
    // TODO: deal with `#integrity` here.
    // If the URL is not a Data URL, the payload MUST contain a sibling claim at the same path suffixed with #integrity containing a [W3C.SRI] hash of the image content.
    case ValueType.Image:
      try {
        return typeof value === 'string' && !!z.url().parse(value)
      } catch {
        return false
      }
    case ValueType.IsoDate:
      try {
        return typeof value === 'string' && !!z.iso.date().parse(value)
      } catch {
        return false
      }
    case ValueType.IsoTime:
      try {
        return typeof value === 'string' && !!z.iso.time().parse(value)
      } catch {
        return false
      }
    case ValueType.IsoDateTime:
      try {
        return typeof value === 'string' && !!z.iso.datetime().parse(value)
      } catch {
        return false
      }
    case ValueType.IsoCurrency:
      try {
        return typeof value === 'string' && !!Iso4217CurrencyCode.parse(value)
      } catch {
        return false
      }
    case ValueType.IsoCurrencyAmount:
      try {
        return typeof value === 'string' && !!Iso4217Amount.parse(value)
      } catch {
        return false
      }
    case ValueType.LabelOnly:
      return true
    case ValueType.MiniMarkdown:
      return typeof value === 'string'
    case ValueType.Url:
      try {
        return typeof value === 'string' && !!z.url().parse(value)
      } catch {
        return false
      }
    default:
      // TODO: allow a way for consumers to add more validation here
      //       add support for `template:${value_type}
      return true
  }
}
