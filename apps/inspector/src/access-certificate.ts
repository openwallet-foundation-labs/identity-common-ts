import { parseAccessCertificate, validateAccessCertificate } from '@owf/eudi-access-certificate'
import { verifyCertificateSignature } from '@owf/x509'
import { type DocumentInput, decodeBinaryText, errorMessage, toText } from './input'
import { type Inspection, InspectionError, type SignatureResult } from './inspection'
import { certificateName, certificateVerifier, outsideValidity, parseKeys } from './signature'

export interface AccessCertificateOptions {
  /** The certificate of the issuing CA, as PEM, base64 or hex */
  issuer?: string
}

/** Text is PEM, base64 or hex; bytes are DER, or one of those as text */
function toCertificateInput(input: DocumentInput): string | Uint8Array {
  if (typeof input !== 'string' && input[0] === 0x30) return input
  const text = toText(input)
  if (!text) throw new InspectionError('There is nothing to inspect')
  if (text.includes('-----BEGIN')) return text
  const der = decodeBinaryText(text)
  if (!der) throw new InspectionError('A certificate is PEM, or DER as base64 or hex, and this is neither')
  return der
}

/** Parse an X.509 certificate and check it against the access certificate profile of ETSI TS 119 411-8 */
export function inspectAccessCertificate(input: DocumentInput, options: AccessCertificateOptions = {}): Inspection {
  let accessCertificate: ReturnType<typeof parseAccessCertificate>
  try {
    accessCertificate = parseAccessCertificate(toCertificateInput(input))
  } catch (error) {
    if (error instanceof InspectionError) throw error
    throw new InspectionError(`This is not a parsable X.509 certificate: ${errorMessage(error)}`)
  }
  const { certificate } = accessCertificate

  const verify = async (): Promise<SignatureResult> => {
    const validity = outsideValidity(certificate)
    if (!options.issuer?.trim()) {
      return {
        status: 'unverified',
        message: `Not verified: give the certificate of the issuing CA to verify it.${validity ? ` Note: ${validity}.` : ''}`,
      }
    }
    let issuers: ReturnType<typeof parseKeys>
    try {
      issuers = parseKeys(options.issuer).filter((key) => key.certificate)
    } catch (error) {
      return { status: 'unverified', message: `Not verified: ${errorMessage(error)}` }
    }
    for (const { certificate: issuer } of issuers) {
      if (issuer && (await verifyCertificateSignature(certificate, issuer, certificateVerifier))) {
        return validity
          ? { status: 'invalid', message: `Signed by ${certificateName(issuer)}, but ${validity}.` }
          : { status: 'valid', message: `Valid, signed by the CA certificate you gave, ${certificateName(issuer)}.` }
      }
    }
    return { status: 'invalid', message: 'Invalid: not signed by the CA certificate you gave.' }
  }

  return {
    kind: 'access-certificate',
    title:
      accessCertificate.policies.length > 0
        ? 'Access certificate (ETSI TS 119 411-8)'
        : 'X.509 certificate, checked as an access certificate',
    checks: ['ETSI TS 119 411-8 certificate profile'],
    notes: ['The revocation status is not checked'],
    value: accessCertificate,
    findings: validateAccessCertificate(accessCertificate).findings,
    signatures: [{ label: 'Signature', verify }],
  }
}
