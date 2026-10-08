import { base64 } from '@owf/identity-common'
import z from 'zod'

/**
 * Standard base64 (RFC 4648 section 4): the base64 alphabet, padded with '=' to a multiple of 4
 * characters.
 */
const BASE64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/

/** The identifier octet of a DER SEQUENCE, which is what a certificate is encoded as. */
const DER_SEQUENCE_TAG = 0x30

/** Why `value` is not standard base64, or `undefined` when it is. */
function standardBase64Issue(value: string): string | undefined {
  if (value === '') return 'it is empty'
  if (/\s/.test(value)) return 'it contains whitespace'
  if (/[-_]/.test(value)) return `it contains '-' or '_', which are base64url characters`
  if (/[^A-Za-z0-9+/=]/.test(value)) return 'it contains a character outside the base64 alphabet'
  if (!BASE64.test(value)) {
    return `its '=' padding is wrong: base64 is padded with at most two '=' at its end, to a multiple of 4 characters`
  }

  // The last character before the padding also holds bits that encode no byte. Decoding ignores them,
  // so they have to be zero for a certificate to have one encoding rather than several.
  if (base64.encode(base64.decode(value)) !== value) {
    return 'it is not the canonical encoding of its bytes: the bits after the last byte are not zero'
  }

  return undefined
}

/**
 * Why `bytes` are not exactly one DER SEQUENCE, or `undefined` when they are.
 *
 * Only the outer element is looked at: its tag, and a definite length in the minimal form DER requires
 * (X.690 section 10.1) that covers exactly the bytes after it. A certificate is far smaller than
 * 2^32 bytes, so a length is encoded in at most 4 bytes.
 */
function derSequenceIssue(bytes: Uint8Array): string | undefined {
  if (bytes[0] !== DER_SEQUENCE_TAG) return 'they do not start with the SEQUENCE tag (0x30)'
  if (bytes.length < 2) return 'they end after the tag, without a length'

  let length = bytes[1]
  let contentStart = 2

  // The long form: the low 7 bits say how many bytes the length takes
  if (length >= 0x80) {
    const lengthSize = length & 0x7f
    if (lengthSize === 0) return 'the length is indefinite (0x80), which DER does not allow'
    if (lengthSize > 4) return 'the length is encoded in more than 4 bytes'
    if (bytes.length < 2 + lengthSize) return 'they end inside the length'

    length = 0
    for (let index = 2; index < 2 + lengthSize; index++) length = length * 256 + bytes[index]

    // DER encodes a length in as few bytes as it takes: without a leading zero byte, and in the short
    // form when it is below 128
    if (bytes[2] === 0 || length < 0x80) return 'the length is not minimally encoded, as DER requires'

    contentStart = 2 + lengthSize
  }

  const available = bytes.length - contentStart
  if (length > available) {
    return `the SEQUENCE is truncated: its length is ${length} byte(s), but only ${available} byte(s) follow`
  }
  if (length < available) return `${available - length} byte(s) follow the SEQUENCE`

  return undefined
}

/**
 * One certificate of an `x5c` parameter: the standard base64 (RFC 4648 section 4, not base64url) of a
 * DER encoded PKIX certificate.
 *
 * Only the encoding is checked: that the value is canonical standard base64 — no base64url
 * characters, no whitespace, '=' padding to a multiple of 4 characters — and that it decodes to
 * exactly one DER SEQUENCE with a definite, minimally encoded length, which is the outer structure
 * of every certificate. The certificate itself is not parsed. Whether it is a valid X.509
 * certificate, whether the chain is in order and chains to a trusted root, and whether the first
 * certificate holds the key that signed is decided where the chain is validated: in the
 * `VerifyJwsCallback`, which is given the `x5c` signer.
 *
 * @see https://www.rfc-editor.org/rfc/rfc7515#section-4.1.6
 * @see https://www.rfc-editor.org/rfc/rfc7517#section-4.7
 */
export const zX5cCertificate = z.string().superRefine((value, ctx) => {
  const base64Issue = standardBase64Issue(value)
  if (base64Issue) {
    ctx.addIssue({
      code: 'custom',
      message: `Expected a certificate in standard base64 (RFC 4648 section 4), but ${base64Issue}`,
    })
    return
  }

  const derIssue = derSequenceIssue(base64.decode(value))
  if (derIssue) {
    ctx.addIssue({
      code: 'custom',
      message: `Expected a DER encoded certificate, but the decoded bytes are not a single DER SEQUENCE: ${derIssue}`,
    })
  }
})

/**
 * An `x5c` (X.509 certificate chain) parameter: one or more certificates, each validated with
 * {@link zX5cCertificate}, the certificate holding the key first. This is the `x5c` of a JWS header,
 * a JWE header and a JWK.
 *
 * An empty chain is rejected: there is no certificate to take the key from.
 *
 * @see https://www.rfc-editor.org/rfc/rfc7515#section-4.1.6
 * @see https://www.rfc-editor.org/rfc/rfc7516#section-4.1.7
 * @see https://www.rfc-editor.org/rfc/rfc7517#section-4.7
 */
export const zX5c = z
  .array(zX5cCertificate)
  .min(1, { message: 'Expected a certificate chain of at least one certificate' })
