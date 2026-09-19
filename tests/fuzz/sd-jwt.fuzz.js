import { hasher } from '@owf/crypto'
import { decodeSdJwt } from '@sd-jwt/core'

export async function fuzz(data) {
  try {
    const input = data.toString('utf-8')
    await decodeSdJwt(input, hasher)
  } catch (_error) {
    // Parser errors on malformed input are expected
  }
}
