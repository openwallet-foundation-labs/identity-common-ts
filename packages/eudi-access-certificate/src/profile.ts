import { type Certificate, type CertificateInput, parseCertificate, telephoneNumbers } from '@owf/x509'
import {
  ACCESS_CERTIFICATE_POLICIES,
  ACCESS_CERTIFICATE_POLICY_INFO,
  type AccessCertificatePolicy,
  type AccessCertificateSubjectType,
} from './constants'
import { parseSemanticIdentifier } from './semantic-identifier'
import type { AccessCertificate } from './types'

const POLICY_BY_OID = new Map<string, AccessCertificatePolicy>(
  Object.entries(ACCESS_CERTIFICATE_POLICIES).map(([name, oid]) => [oid, name as AccessCertificatePolicy])
)

function deriveSubjectType(
  policies: AccessCertificatePolicy[],
  certificate: Certificate
): AccessCertificateSubjectType | undefined {
  const types = new Set(policies.map((p) => ACCESS_CERTIFICATE_POLICY_INFO[p].subjectType))
  if (types.size === 1) return [...types][0]
  if (types.size > 1) return undefined
  const { subject } = certificate
  if (subject.organizationIdentifier) return 'legal'
  if (subject.givenName || subject.surname || subject.pseudonym) return 'natural'
  return undefined
}

/**
 * Interpret a parsed X.509 certificate as a wallet-relying party access certificate
 * (ETSI TS 119 411-8). This does not check conformance; use {@link validateAccessCertificate}.
 */
export function toAccessCertificate(certificate: Certificate): AccessCertificate {
  const policies = certificate.policies
    .map((p) => POLICY_BY_OID.get(p.oid))
    .filter((p): p is AccessCertificatePolicy => p !== undefined)
  const subjectType = deriveSubjectType(policies, certificate)
  const identifier =
    subjectType === 'natural' ? certificate.subject.serialNumber : certificate.subject.organizationIdentifier
  const san = certificate.subjectAlternativeNames

  return {
    certificate,
    policies,
    subjectType,
    qualified: policies.some((p) => ACCESS_CERTIFICATE_POLICY_INFO[p].qualified),
    subjectIdentifier: identifier ? parseSemanticIdentifier(identifier) : undefined,
    contact: { uris: san.uris, emails: san.emails, phoneNumbers: telephoneNumbers(san) },
  }
}

/**
 * Parse a wallet-relying party access certificate (ETSI TS 119 411-8).
 *
 * Shorthand for `toAccessCertificate(parseCertificate(input))`. Parsing only decodes the
 * certificate; it does not check it against the profile or verify its signature.
 *
 * @param input DER bytes, base64 encoded DER, or PEM
 * @throws X509Exception when the input is not a well-formed X.509 certificate
 */
export function parseAccessCertificate(input: CertificateInput): AccessCertificate {
  return toAccessCertificate(parseCertificate(input))
}

/**
 * The semantic identifier of the wallet-relying party, i.e. the `organizationIdentifier`
 * for legal persons or the `serialNumber` for natural persons. This is the value a
 * registration certificate (ETSI TS 119 475) is bound to via its `sub` claim.
 */
export function getAccessCertificateSubjectIdentifier(accessCertificate: AccessCertificate): string | undefined {
  const { subject } = accessCertificate.certificate
  return accessCertificate.subjectType === 'natural' ? subject.serialNumber : subject.organizationIdentifier
}
