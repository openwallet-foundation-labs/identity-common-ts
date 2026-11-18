import { z } from 'zod'
import { DcqlMdocCredential, DcqlSdJwtVcCredential, DcqlW3cVcCredential } from '../u-dcql-credential.js'

export namespace DcqlMdocPresentation {
  export const zModel = DcqlMdocCredential.zModel
  export type Model = DcqlMdocCredential.Model
}
export type DcqlMdocPresentation = DcqlMdocPresentation.Model['Output']

export namespace DcqlSdJwtVcPresentation {
  export const zModel = DcqlSdJwtVcCredential.zModel
  export type Model = DcqlSdJwtVcCredential.Model
}
export type DcqlSdJwtVcPresentation = DcqlSdJwtVcPresentation.Model['Output']

export namespace DcqlW3cVcPresentation {
  export const zModel = DcqlW3cVcCredential.zModel
  export type Model = DcqlW3cVcCredential.Model
}
export type DcqlW3cVcPresentation = DcqlW3cVcPresentation.Model['Output']

export namespace DcqlCredentialPresentation {
  export const zModel = z.union([
    DcqlMdocPresentation.zModel,
    DcqlSdJwtVcPresentation.zModel,
    DcqlW3cVcPresentation.zModel,
  ])
  export type Model = { Input: z.input<typeof zModel>; Output: z.output<typeof zModel> }
}
export type DcqlCredentialPresentation = DcqlCredentialPresentation.Model['Output']
