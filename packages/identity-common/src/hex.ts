import { IdentityCommonException } from './identity-common-exception'

const HEX_CHARS = '0123456789abcdef'

const bytesToHex = (bytes: Uint8Array): string => {
  let result = ''
  for (let i = 0; i < bytes.length; i++) {
    result += HEX_CHARS[(bytes[i] >> 4) & 0x0f]
    result += HEX_CHARS[bytes[i] & 0x0f]
  }
  return result
}

const hexToBytes = (hex: string): Uint8Array => {
  // Validate input - only hex characters are allowed
  const validHexRegex = /^[0-9a-fA-F]*$/
  if (!validHexRegex.test(hex)) {
    throw new IdentityCommonException('Invalid hex string: contains invalid characters')
  }

  // Handle odd-length hex strings by padding with leading zero
  if (hex.length % 2 !== 0) {
    hex = `0${hex}`
  }

  const bytes = new Uint8Array(hex.length / 2)
  for (let i = 0; i < hex.length; i += 2) {
    const high = HEX_CHARS.indexOf(hex[i].toLowerCase())
    const low = HEX_CHARS.indexOf(hex[i + 1].toLowerCase())
    bytes[i / 2] = (high << 4) | low
  }
  return bytes
}

// Public API - keeping backward compatible names
export const hexEncode = (input: Uint8Array): string => bytesToHex(input)

export const hexDecode = (input: string): Uint8Array => hexToBytes(input)

// Additional exports for flexibility
export const hex = {
  encode: bytesToHex,
  decode: hexToBytes,
}
