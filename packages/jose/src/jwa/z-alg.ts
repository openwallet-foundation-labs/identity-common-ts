import z from 'zod'

/**
 * A JWS `alg` value.
 *
 * Any algorithm identifier is accepted, as the registry is open and which algorithms are acceptable
 * is a policy decision made at verification time — except `none`, which is rejected here so that an
 * unsecured JWS cannot enter the library at all.
 *
 * @see https://www.rfc-editor.org/rfc/rfc7515#section-4.1.1
 * @see https://www.rfc-editor.org/rfc/rfc8725#section-3.2
 */
export const zJwsAlg = z
  .string()
  // An empty string is not an algorithm identifier, registered or otherwise
  .min(1)
  .refine(
    // `None`, `NONE`, ... are not registered values either, but a case-insensitive comparison
    // somewhere downstream should not be able to turn one into an unsecured token.
    (alg) => alg.toLowerCase() !== 'none',
    { message: `alg value may not be 'none'` }
  )

/** A JWE `alg` (key management algorithm) value. @see https://www.rfc-editor.org/rfc/rfc7516#section-4.1.1 */
export const zJweAlg = z.string()

/** A JWE `enc` (content encryption algorithm) value. @see https://www.rfc-editor.org/rfc/rfc7516#section-4.1.2 */
export const zJweEnc = z.string()
