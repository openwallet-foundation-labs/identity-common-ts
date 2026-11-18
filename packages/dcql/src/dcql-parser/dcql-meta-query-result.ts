import { z } from 'zod'
import { DcqlError } from '../dcql-error/e-base.js'
import type { DcqlCredentialQuery } from '../dcql-query/m-dcql-credential-query.js'
import type { DcqlMetaResult } from '../dcql-query-result/m-meta-result.js'
import { DCQL_VALIDATION_CODES, parseDcql, zMatch, zNonEmptyArray } from '../u-dcql.js'
import type { DcqlCredential } from '../u-dcql-credential.js'

const zCredentialFormat = <Format extends string>(format: Format) =>
  zMatch<Format>(
    (value) => value === format,
    (value) => ({
      code: DCQL_VALIDATION_CODES.CREDENTIAL_FORMAT_MISMATCH,
      message: `Expected credential format to be '${format}' but received '${value}'`,
      context: { expected: format, actual: value },
    })
  )

const getCryptographicHolderBindingValue = (credentialQuery: DcqlCredentialQuery) =>
  z.object({
    cryptographic_holder_binding: credentialQuery.require_cryptographic_holder_binding
      ? zMatch<true>(
          (value) => value === true,
          (value) => ({
            code: DCQL_VALIDATION_CODES.CRYPTOGRAPHIC_HOLDER_BINDING_REQUIRED,
            message: `Expected cryptographic_holder_binding to be true (because credential query '${credentialQuery.id}' requires cryptographic holder binding), but received ${value}`,
          })
        )
      : z.boolean(),
  })

const getMdocMetaParser = (credentialQuery: DcqlCredentialQuery.Mdoc) => {
  const doctypeValue = credentialQuery.meta?.doctype_value
  const zDoctype = doctypeValue
    ? zMatch<string>(
        (value) => value === doctypeValue,
        (value) => ({
          code: DCQL_VALIDATION_CODES.DOCTYPE_MISMATCH,
          message: `Expected doctype to be '${doctypeValue}' but received '${value}'`,
          context: { expected: doctypeValue, actual: value },
        })
      )
    : z.string('Expected doctype to be defined')

  return getCryptographicHolderBindingValue(credentialQuery).extend({
    credential_format: zCredentialFormat('mso_mdoc'),
    doctype: zDoctype,
  })
}

const getSdJwtVcMetaParser = (credentialQuery: DcqlCredentialQuery.SdJwtVc) => {
  const vctValues = credentialQuery.meta?.vct_values

  return getCryptographicHolderBindingValue(credentialQuery).extend({
    credential_format: zCredentialFormat(credentialQuery.format),
    vct: vctValues
      ? zMatch<string>(
          (value) => vctValues.includes(value as string),
          (value) => ({
            code: DCQL_VALIDATION_CODES.VCT_MISMATCH,
            message: `Expected vct to be '${vctValues.join("' | '")}' but received '${value}'`,
            context: { expected: vctValues, actual: value },
          })
        )
      : z.string({
          error: (issue) => (issue.input === undefined ? 'Expected vct to be defined' : 'Expected vct to be a string'),
        }),
  })
}

const getW3cVcMetaParser = (credentialQuery: DcqlCredentialQuery.W3cVc) => {
  const typeValues = credentialQuery.meta?.type_values

  return getCryptographicHolderBindingValue(credentialQuery).extend({
    credential_format: zCredentialFormat(credentialQuery.format),
    type: typeValues
      ? zMatch<string[]>(
          (type) => Array.isArray(type) && typeValues.some((values) => values.every((value) => type.includes(value))),
          (type) => ({
            code: DCQL_VALIDATION_CODES.TYPE_MISMATCH,
            message: `Expected type to include all values from one of the following subsets: ${typeValues
              .map((values) => `[${values.join(', ')}]`)
              .join(' | ')}`,
            context: { expected: typeValues, actual: type },
          })
        )
      : zNonEmptyArray(z.string()),
  })
}

export const getMetaParser = (credentialQuery: DcqlCredentialQuery) => {
  if (credentialQuery.format === 'mso_mdoc') {
    return getMdocMetaParser(credentialQuery)
  }

  if (credentialQuery.format === 'dc+sd-jwt') {
    return getSdJwtVcMetaParser(credentialQuery)
  }

  if (credentialQuery.format === 'vc+sd-jwt') {
    if (credentialQuery.meta && 'type_values' in credentialQuery.meta) {
      return getW3cVcMetaParser(credentialQuery as DcqlCredentialQuery.W3cVc)
    }

    return getSdJwtVcMetaParser(credentialQuery as DcqlCredentialQuery.SdJwtVc)
  }

  if (credentialQuery.format === 'ldp_vc' || credentialQuery.format === 'jwt_vc_json') {
    return getW3cVcMetaParser(credentialQuery)
  }

  throw new DcqlError({
    code: 'NOT_IMPLEMENTED',
    message: `Unsupported format '${credentialQuery.format}'`,
  })
}

export const runMetaQuery = (credentialQuery: DcqlCredentialQuery, credential: DcqlCredential): DcqlMetaResult => {
  const metaParser = getMetaParser(credentialQuery)
  const parseResult = parseDcql(metaParser, credential)

  if (!parseResult.success) {
    return {
      success: false,
      issues: parseResult.issues,
    }
  }

  return {
    success: true,
    output: parseResult.data,
  }
}
