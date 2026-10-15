import { hex } from '@owf/identity-common'

/**
 * The key identifiers of a certificate: the `keyIdentifier` of its authority key identifier and its
 * subject key identifier (RFC 5280 4.2.1.1 and 4.2.1.2).
 *
 * ISO/IEC TS 23220-4 7.2.1.3.2 matches `issuerIdentifiers` against the authority key identifier of a
 * certificate in the x5chain of the IssuerAuth, and notes that a reader passing the subject key
 * identifier of the certificate it verifies an issuer with matches one too, so both are returned.
 *
 * Matching runs without the `x509` context, so this reads the two extensions straight from the DER.
 * A certificate that does not parse yields no identifier rather than an error.
 */
export const certificateKeyIdentifiers = (certificate: Uint8Array): Array<Uint8Array> => {
  try {
    const [certificateSequence] = readTlvs(certificate)
    const [tbsCertificate] = readTlvs(certificateSequence.value)
    // [3] EXPLICIT Extensions, after the optional issuer and subject unique identifiers.
    const extensionsField = readTlvs(tbsCertificate.value).find((tlv) => tlv.tag === 0xa3)
    if (!extensionsField) return []

    const [extensions] = readTlvs(extensionsField.value)
    const identifiers: Array<Uint8Array> = []
    for (const extension of readTlvs(extensions.value)) {
      const [extensionId, ...rest] = readTlvs(extension.value)
      // extnValue is the last element; `critical` may come before it.
      const extensionValue = rest[rest.length - 1]
      if (extensionId?.tag !== 0x06 || extensionValue?.tag !== 0x04) continue

      const oid = hex.encode(extensionId.value)
      if (oid === SUBJECT_KEY_IDENTIFIER) {
        const [keyIdentifier] = readTlvs(extensionValue.value)
        if (keyIdentifier?.tag === 0x04) identifiers.push(keyIdentifier.value)
      } else if (oid === AUTHORITY_KEY_IDENTIFIER) {
        const [authorityKeyIdentifier] = readTlvs(extensionValue.value)
        // keyIdentifier is [0] IMPLICIT, the primitive context-specific tag 0x80.
        const keyIdentifier =
          authorityKeyIdentifier && readTlvs(authorityKeyIdentifier.value).find((t) => t.tag === 0x80)
        if (keyIdentifier) identifiers.push(keyIdentifier.value)
      }
    }
    return identifiers
  } catch {
    return []
  }
}

/** 2.5.29.14 and 2.5.29.35, as DER object identifier contents. */
const SUBJECT_KEY_IDENTIFIER = '551d0e'
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
