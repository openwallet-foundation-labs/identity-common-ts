import { addValidationIssue, zNonEmptyString } from '@owf/identity-common'

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
export const zJwsAlg = zNonEmptyString.superRefine((alg, ctx) => {
  // `None`, `NONE`, ... are not registered values either, but a case-insensitive comparison
  // somewhere downstream should not be able to turn one into an unsecured token.
  if (alg.toLowerCase() === 'none') {
    addValidationIssue(ctx, { code: 'invalid_value', message: `alg value may not be 'none'` })
  }
})

/** A JWE `alg` (key management algorithm) value. @see https://www.rfc-editor.org/rfc/rfc7516#section-4.1.1 */
export const zJweAlg = zNonEmptyString

/** A JWE `enc` (content encryption algorithm) value. @see https://www.rfc-editor.org/rfc/rfc7516#section-4.1.2 */
export const zJweEnc = zNonEmptyString
