import { z } from 'zod'

export const swapValidators = <T extends z.ZodRawShape, V extends z.ZodType>(
  schema: z.ZodObject<T>,
  newValidator: V
): z.ZodObject<{ [K in keyof T]: V }> => {
  return z.object(
    Object.keys(schema.shape).reduce(
      (acc, key) => {
        acc[key as keyof typeof acc] = newValidator
        return acc
      },
      {} as { [K in keyof T]: V }
    )
  )
}
