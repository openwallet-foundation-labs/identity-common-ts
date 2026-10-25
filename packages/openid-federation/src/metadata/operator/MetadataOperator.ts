import type { z } from 'zod'
import type { MetadataMergeStrategy } from './MetadataMergeStrategy'
import type { MetadataOrderOfApplication } from './MetadataOrderOfApplication'

export type MetadataOperator<TKey extends string> = {
  key: TKey
  parameterJsonValues: Array<z.ZodType>
  operatorJsonValues: Array<z.ZodType>
  canBeCombinedWith: Array<string>
  orderOfApplication: MetadataOrderOfApplication
  mergeStrategy: MetadataMergeStrategy
}
