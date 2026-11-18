import { addValidationIssue, base64 } from '@owf/identity-common'
import z from 'zod'

/** The identifier octet of a DER SEQUENCE, which is what a certificate is encoded as. */
const DER_SEQUENCE_TAG = 0x30

/**
 * Why `bytes` are not exactly one DER SEQUENCE with a minimal definite length (X.690 section 10.1), or
 * `undefined`. A certificate is far below 2^32 bytes, so a longer length encoding is rejected.
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

    // DER: no leading zero byte, and the short form below 128
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
 * One `x5c` certificate: standard base64 (RFC 4648 section 4, not base64url) of one DER SEQUENCE. The
 * certificate is not parsed: the `VerifyJwsCallback` validates the chain.
 *
 * @see https://www.rfc-editor.org/rfc/rfc7515#section-4.1.6
 * @see https://www.rfc-editor.org/rfc/rfc7517#section-4.7
 */
export const zX5cCertificate = z
  .base64({ message: 'Expected a certificate in standard base64 (RFC 4648 section 4)' })
  .superRefine((value, ctx) => {
    // zod runs the refinement also when the value is not base64
    if (!z.core.regexes.base64.test(value)) return

    const derIssue = derSequenceIssue(base64.decode(value))
    if (derIssue) {
      addValidationIssue(ctx, {
        code: 'invalid_format',
        message: `Expected a DER encoded certificate, but the decoded bytes are not a single DER SEQUENCE: ${derIssue}`,
        context: { format: 'der' },
      })
    }
  })

/**
 * The `x5c` of a JWS header, JWE header or JWK: one or more certificates, the one holding the key first.
 *
 * @see https://www.rfc-editor.org/rfc/rfc7515#section-4.1.6
 * @see https://www.rfc-editor.org/rfc/rfc7516#section-4.1.7
 * @see https://www.rfc-editor.org/rfc/rfc7517#section-4.7
 */
export const zX5c = z
  .array(zX5cCertificate)
  .min(1, { message: 'Expected a certificate chain of at least one certificate' })
