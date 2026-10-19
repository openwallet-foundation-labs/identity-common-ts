import { base64url, base64urlDecodeJson } from '@owf/identity-common'
import { z } from 'zod'
import { validate } from '../utils/validate'

const defaultSchema = z.record(z.string(), z.unknown())

/**
 *
 * @todo better jwt validation
 *
 */
export const jsonWebTokenSchema = <
  CS extends z.ZodType = typeof defaultSchema,
  HS extends z.ZodType = typeof defaultSchema,
>(
  {
    claimsSchema = defaultSchema as unknown as CS,
    headerSchema = defaultSchema as unknown as HS,
  }: {
    claimsSchema?: CS
    headerSchema?: HS
  } = {
    claimsSchema: defaultSchema as unknown as CS,
    headerSchema: defaultSchema as unknown as HS,
  }
) =>
  z.string().transform((s, ctx) => {
    const [header, claims, signature] = s.split('.')

    if (!header) {
      ctx.addIssue({
        code: 'custom',
        message: 'JWT does not contain a header parameter',
      })
      return z.NEVER
    }

    if (!claims) {
      ctx.addIssue({
        code: 'custom',
        message: 'JWT does not contain a payload',
      })
      return z.NEVER
    }

    if (!signature) {
      ctx.addIssue({
        code: 'custom',
        message: 'JWT does not contain a signature',
      })

      return z.NEVER
    }

    let decodedHeader: unknown
    let decodedClaims: unknown
    let decodedSignature: Uint8Array
    try {
      decodedHeader = base64urlDecodeJson(header)
      decodedClaims = base64urlDecodeJson(claims)
      decodedSignature = base64url.decode(signature)
    } catch {
      ctx.addIssue({
        code: 'custom',
        message: 'JWT is not a valid compact JWS',
      })
      return z.NEVER
    }

    const validatedHeader = validate({
      schema: headerSchema,
      data: decodedHeader,
      errorMessage: 'invalid header claims provided',
    })
    const validatedClaims = validate({
      schema: claimsSchema,
      data: decodedClaims,
      errorMessage: 'invalid payload claims provided',
    })

    return {
      jwt: s,
      header: validatedHeader,
      claims: validatedClaims,
      signature: decodedSignature,
    }
  })
