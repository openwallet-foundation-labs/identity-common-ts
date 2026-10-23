import { base64urlEncode, stringToBytes } from '@owf/identity-common'

/**
 *
 * Converts a JSON header and payload into a byte array which can be used to verify and sign a JWT
 *
 */
export const createJwtSignableInput = (header: Record<string, unknown>, payload: Record<string, unknown>) => {
  if (Object.keys(header).length === 0) {
    throw new Error('Can not create JWT with an empty header')
  }

  if (Object.keys(payload).length === 0) {
    throw new Error('Can not create JWT with an empty payload')
  }

  const encodedHeader = base64urlEncode(JSON.stringify(header))
  const encodedPayload = base64urlEncode(JSON.stringify(payload))

  const toBeSignedString = `${encodedHeader}.${encodedPayload}`

  return stringToBytes(toBeSignedString)
}
