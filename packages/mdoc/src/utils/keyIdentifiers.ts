import { hex } from '@owf/identity-common'

/**
 * The `keyIdentifier` of the authority key identifier of a certificate (RFC 5280 4.2.1.1), which
 * ISO/IEC TS 23220-4 7.2.1.3.2 and 18013-5 second edition 10.2.4 match `issuerIdentifiers` against.
 * It is the subject key identifier of the certificate that issued it, so a reader names an issuer
 * by the subject key identifier of its IACA or issuing CA.
 *
 * Matching runs without the `x509` context, so this reads the extension straight from the DER. A
 * certificate that does not parse, or has no such extension, yields undefined rather than an error.
 */
export const certificateAuthorityKeyIdentifier = (certificate: Uint8Array): Uint8Array | undefined => {
  try {
    const [certificateSequence] = readTlvs(certificate)
    const [tbsCertificate] = readTlvs(certificateSequence.value)
    // [3] EXPLICIT Extensions, after the optional issuer and subject unique identifiers.
    const extensionsField = readTlvs(tbsCertificate.value).find((tlv) => tlv.tag === 0xa3)
    if (!extensionsField) return undefined

    const [extensions] = readTlvs(extensionsField.value)
    for (const extension of readTlvs(extensions.value)) {
      const [extensionId, ...rest] = readTlvs(extension.value)
      // extnValue is the last element; `critical` may come before it.
      const extensionValue = rest[rest.length - 1]
      if (extensionId?.tag !== 0x06 || extensionValue?.tag !== 0x04) continue
      if (hex.encode(extensionId.value) !== AUTHORITY_KEY_IDENTIFIER) continue

      const [authorityKeyIdentifier] = readTlvs(extensionValue.value)
      // keyIdentifier is [0] IMPLICIT, the primitive context-specific tag 0x80.
      return authorityKeyIdentifier && readTlvs(authorityKeyIdentifier.value).find((t) => t.tag === 0x80)?.value
    }
    return undefined
  } catch {
    return undefined
  }
}

/** 2.5.29.35, as DER object identifier contents. */
const AUTHORITY_KEY_IDENTIFIER = '551d23'

type Tlv = { tag: number; value: Uint8Array }

/** The DER TLVs laid end to end in `bytes`. Throws on a truncated or indefinite length. */
const readTlvs = (bytes: Uint8Array): Array<Tlv> => {
  const tlvs: Array<Tlv> = []
  let offset = 0
  while (offset < bytes.length) {
    const tag = bytes[offset]
    let length = bytes[offset + 1]
    let headerLength = 2
    if (length & 0x80) {
      const lengthBytes = length & 0x7f
      if (lengthBytes === 0 || lengthBytes > 4) throw new Error('Unsupported DER length')
      length = 0
      for (let i = 0; i < lengthBytes; i++) length = length * 256 + bytes[offset + 2 + i]
      headerLength += lengthBytes
    }
    if (offset + headerLength + length > bytes.length) throw new Error('Truncated DER')
    tlvs.push({ tag, value: bytes.subarray(offset + headerLength, offset + headerLength + length) })
    offset += headerLength + length
  }
  return tlvs
}
