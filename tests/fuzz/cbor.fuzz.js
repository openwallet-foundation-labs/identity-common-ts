import { cborDecode } from '@owf/cose'

export function fuzz(data) {
  try {
    cborDecode(new Uint8Array(data))
  } catch (_error) {
    // Decoding errors on malformed byte inputs are expected
  }
}
