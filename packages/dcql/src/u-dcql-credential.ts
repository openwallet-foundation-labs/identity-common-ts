import { z } from 'zod'
import { DcqlCredentialTrustedAuthority } from './dcql-query/m-dcql-trusted-authorities.js'
import { zJsonRecord } from './u-dcql.js'

const zCredentialModelBase = z.object({
  authority: DcqlCredentialTrustedAuthority.zModel.optional(),

  /**
   * Indicates support/inclusion of cryptographic holder binding. This will be checked against
   * the `require_cryptographic_holder_binding` property from the query.
   *
   * In the context of a presentation this value means whether the presentation is created
   * with cryptographic holder binding. In the context of a credential query this means whether
   * the credential supports cryptographic holder binding.
   */
  cryptographic_holder_binding: z
    .boolean()
    .describe(
      'Indicates support/inclusion of cryptographic holder binding. This will be checked against the `require_cryptographic_holder_binding` property from the query.'
    ),
})

export namespace DcqlMdocCredential {
  export const zNamespaces = z.record(z.string(), z.record(z.string(), z.unknown()))
  export const zModel = zCredentialModelBase.extend({
    credential_format: z.literal('mso_mdoc'),
    doctype: z.string(),
    namespaces: zNamespaces,
  })

  export type Model = { Input: z.input<typeof zModel>; Output: z.output<typeof zModel> }
  export type NameSpaces = z.output<typeof zNamespaces>
}
export type DcqlMdocCredential = DcqlMdocCredential.Model['Output']

export namespace DcqlSdJwtVcCredential {
  export const zClaims = zJsonRecord
  export const zModel = zCredentialModelBase.extend({
    credential_format: z.enum(['vc+sd-jwt', 'dc+sd-jwt']),
    vct: z.string(),
    claims: zClaims,
  })
  export type Model = { Input: z.input<typeof zModel>; Output: z.output<typeof zModel> }
  export type Claims = Model['Output']['claims']
}
export type DcqlSdJwtVcCredential = DcqlSdJwtVcCredential.Model['Output']

export namespace DcqlW3cVcCredential {
  export const zClaims = zJsonRecord
  export const zModel = zCredentialModelBase.extend({
    credential_format: z.enum(['ldp_vc', 'jwt_vc_json', 'vc+sd-jwt']),
    claims: zClaims,
    type: z.array(z.string()),
  })

  export type Model = { Input: z.input<typeof zModel>; Output: z.output<typeof zModel> }
  export type Claims = Model['Output']['claims']
}
export type DcqlW3cVcCredential = DcqlW3cVcCredential.Model['Output']

export namespace DcqlCredential {
  // Not a discriminated union, as vc+sd-jwt is both an SD-JWT VC and a W3C VC format
  export const zModel = z.union([DcqlMdocCredential.zModel, DcqlSdJwtVcCredential.zModel, DcqlW3cVcCredential.zModel])

  export type Model = { Input: z.input<typeof zModel>; Output: z.output<typeof zModel> }
}
export type DcqlCredential = DcqlCredential.Model['Output']
