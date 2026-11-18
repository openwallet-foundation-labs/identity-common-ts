import { z } from 'zod'
import { zIssues } from '../u-dcql.js'
import { DcqlMdocCredential, DcqlSdJwtVcCredential, DcqlW3cVcCredential } from '../u-dcql-credential.js'

export namespace DcqlMetaResult {
  export const zMetaSuccessResult = z.object({
    success: z.literal(true),

    output: z.union([
      DcqlSdJwtVcCredential.zModel.pick({ credential_format: true, cryptographic_holder_binding: true, vct: true }),
      DcqlMdocCredential.zModel.pick({ credential_format: true, cryptographic_holder_binding: true, doctype: true }),
      DcqlW3cVcCredential.zModel.pick({ credential_format: true, cryptographic_holder_binding: true, type: true }),
    ]),
  })

  export const zMetaFailureResult = z.object({
    success: z.literal(false),
    issues: zIssues,
  })

  export const zModel = z.union([zMetaSuccessResult, zMetaFailureResult])
  export type Input = z.input<typeof zModel>
  export type Output = z.output<typeof zModel>
}
export type DcqlMetaResult = DcqlMetaResult.Output
