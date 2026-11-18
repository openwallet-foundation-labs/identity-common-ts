import { z } from 'zod'
import { addDcqlIssue, base64urlRegex, DCQL_VALIDATION_CODES, isObject, zNonEmptyArray } from '../u-dcql.js'

const formatInput = (input: unknown) => (typeof input === 'string' ? `'${input}'` : `${input}`)

export const getTrustedAuthorityParser = (trustedAuthority: DcqlTrustedAuthoritiesQuery) =>
  z
    .custom<DcqlCredentialTrustedAuthority>()
    .superRefine((authority, ctx) => {
      const addIssue = (message: string, path: string[] = []) =>
        addDcqlIssue(ctx, {
          code: DCQL_VALIDATION_CODES.TRUSTED_AUTHORITY_MISMATCH,
          path,
          message,
          context: { expected: trustedAuthority, actual: authority },
        })

      if (!isObject(authority)) {
        addIssue(
          `Expected trusted authority object with type '${trustedAuthority.type}' to be defined, but received undefined`
        )
        return
      }
      if (authority.type !== trustedAuthority.type) {
        addIssue(
          `Expected trusted authority type to be '${trustedAuthority.type}' but received ${formatInput(authority.type)}`,
          ['type']
        )
      }
      // Some trusted authorities support an array as input type
      const values: unknown[] = Array.isArray(authority.values) ? authority.values : []
      if (!values.some((value) => trustedAuthority.values.includes(value as string))) {
        addIssue(
          `Expected one of the trusted authority values to be '${trustedAuthority.values.join("' | '")}' but received '${values.join("' , '")}'`,
          ['values']
        )
      }
    })
    .transform(({ type, values }) => ({
      type,
      value: values.find((value) => trustedAuthority.values.includes(value)) as string,
    }))

const typeDescription =
  'REQUIRED. A string uniquely identifying the type of information about the issuer trust framework.'
const valuesDescription =
  'REQUIRED. An array of strings, where each string (value) contains information specific to the used Trusted Authorities Query type that allows to identify an issuer, trust framework, or a federation that an issuer belongs to.'

const zAuthorityKeyIdentifier = z.object({
  type: z.literal('aki').describe(typeDescription),
  values: zNonEmptyArray(
    z
      .string('aki trusted authority value must be a string')
      .regex(base64urlRegex, 'aki trusted authority value must be base64url')
      .describe(
        'Contains a list of KeyIdentifier entries of the AuthorityKeyIdentifier as defined in Section 4.2.1.1 of [RFC5280], encoded as base64url. The raw byte representation of one of the elements MUST match with the AuthorityKeyIdentifier element of an X.509 certificate in the certificate chain present in the credential (e.g., in the header of an mdoc or SD-JWT). Note that the chain can consist of a single certificate and the credential can include the entire X.509 chain or parts of it.'
      )
  ).describe(valuesDescription),
})

const zEtsiTrustedList = z.object({
  type: z.literal('etsi_tl').describe(typeDescription),
  values: zNonEmptyArray(
    z
      .url({
        protocol: /^https?$/,
        error: (issue) =>
          typeof issue.input === 'string'
            ? 'etsi_tl trusted authority value must be a valid https url'
            : 'etsi_tl trusted authority value must be a string',
      })
      .describe(
        'The identifier of a Trusted List as specified in ETSI TS 119 612 [ETSI.TL]. An ETSI Trusted List contains references to other Trusted Lists, creating a list of trusted lists, or entries for Trust Service Providers with corresponding service description and X.509 Certificates. The trust chain of a matching Credential MUST contain at least one X.509 Certificate that matches one of the entries of the Trusted List or its cascading Trusted Lists.'
      )
  ).describe(valuesDescription),
})

const zOpenidFederation = z.object({
  type: z.literal('openid_federation').describe(typeDescription),
  values: zNonEmptyArray(
    z
      // TODO: should we have a config similar to oid4vc-ts to support http for development?
      .url({
        protocol: /^https?$/,
        error: (issue) =>
          typeof issue.input === 'string'
            ? 'openid_federation trusted authority value must be a valid https url'
            : 'openid_federation trusted authority value must be a string',
      })
      .describe(
        'The Entity Identifier as defined in Section 1 of [OpenID.Federation] that is bound to an entity in a federation. While this Entity Identifier could be any entity in that ecosystem, this entity would usually have the Entity Configuration of a Trust Anchor. A valid trust path, including the given Entity Identifier, must be constructible from a matching credential.'
      )
  ).describe(valuesDescription),
})

/**
 * Specifies trusted authorities within a requested Credential.
 */
export namespace DcqlTrustedAuthoritiesQuery {
  export const zModel = z.discriminatedUnion('type', [zAuthorityKeyIdentifier, zEtsiTrustedList, zOpenidFederation], {
    error: `Expected type to be one of 'aki', 'etsi_tl' or 'openid_federation'`,
  })
  export type Input = z.input<typeof zModel>
  export type Out = z.output<typeof zModel>
}
export type DcqlTrustedAuthoritiesQuery = DcqlTrustedAuthoritiesQuery.Out

/**
 * Specifies trusted authorities within a requested Credential.
 */
export namespace DcqlCredentialTrustedAuthority {
  export const zModel = DcqlTrustedAuthoritiesQuery.zModel
  export type Input = z.input<typeof zModel>
  export type Out = z.output<typeof zModel>
}
export type DcqlCredentialTrustedAuthority = DcqlCredentialTrustedAuthority.Out
