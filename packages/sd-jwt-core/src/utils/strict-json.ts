import { base64urlDecodeJson } from '@owf/identity-common'
import { SDJWTException } from './error'

/**
 * Decode base64url encoded JSON with {@link base64urlDecodeJson}, rethrowing failures as an
 * `SDJWTException` with the given message.
 */
export const decodeBase64urlJsonStrict = <T>(encoded: string, errorMessage: string): T => {
  try {
    return base64urlDecodeJson<T>(encoded)
  } catch {
    throw new SDJWTException(errorMessage)
  }
}
