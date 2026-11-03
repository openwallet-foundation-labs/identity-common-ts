import { addValidationIssue, zNonEmptyString } from '@owf/identity-common'

/**
 * A JWS `alg`. The registry is open and the allowed algorithms are checked at verification, so any
 * value is accepted except `none`, in any casing.
 *
 * @see https://www.rfc-editor.org/rfc/rfc7515#section-4.1.1
 * @see https://www.rfc-editor.org/rfc/rfc8725#section-3.2
 */
export const zJwsAlg = zNonEmptyString.superRefine((alg, ctx) => {
  if (alg.toLowerCase() === 'none') {
    addValidationIssue(ctx, { code: 'invalid_value', message: `alg value may not be 'none'` })
  }
})

/** A JWE `alg` (key management algorithm) value. @see https://www.rfc-editor.org/rfc/rfc7516#section-4.1.1 */
export const zJweAlg = zNonEmptyString

/** A JWE `enc` (content encryption algorithm) value. @see https://www.rfc-editor.org/rfc/rfc7516#section-4.1.2 */
export const zJweEnc = zNonEmptyString
