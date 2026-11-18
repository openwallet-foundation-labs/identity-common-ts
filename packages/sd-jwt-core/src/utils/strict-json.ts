import { base64urlDecodeJson } from '@owf/identity-common'
import { SdJwtError } from './error'

/**
 * Decode base64url encoded JSON with {@link base64urlDecodeJson}, rethrowing failures as an
 * `SdJwtError` with the given message.
 */
export const decodeBase64urlJsonStrict = <T>(encoded: string, errorMessage: string): T => {
  try {
    return base64urlDecodeJson<T>(encoded)
  } catch {
    throw new SdJwtError(errorMessage)
  }
}
