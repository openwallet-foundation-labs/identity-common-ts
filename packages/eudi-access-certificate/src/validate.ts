import type { CertificateInput } from '@owf/x509'
import { AccessCertificateException } from './access-certificate-exception'
import { ACCESS_CERTIFICATE_POLICY_INFO } from './constants'
import { parseAccessCertificate } from './profile'
import { parseSemanticIdentifier } from './semantic-identifier'
import type {
  AccessCertificate,
  AccessCertificateValidationIssue,
  AccessCertificateValidationOptions,
  AccessCertificateValidationSeverity,
} from './types'

export const ACCESS_CERTIFICATE_VALIDATION_CODES = {
  UNSUPPORTED_VERSION: 'UNSUPPORTED_VERSION',
  NOT_YET_VALID: 'NOT_YET_VALID',
  EXPIRED: 'EXPIRED',
  CA_CERTIFICATE: 'CA_CERTIFICATE',
  MISSING_DIGITAL_SIGNATURE_KEY_USAGE: 'MISSING_DIGITAL_SIGNATURE_KEY_USAGE',
  MISSING_POLICY: 'MISSING_POLICY',
  CONFLICTING_POLICIES: 'CONFLICTING_POLICIES',
  MISSING_CPS_URI: 'MISSING_CPS_URI',
  MISSING_CONTACT: 'MISSING_CONTACT',
  UNKNOWN_SUBJECT_TYPE: 'UNKNOWN_SUBJECT_TYPE',
  MISSING_COMMON_NAME: 'MISSING_COMMON_NAME',
  MISSING_COUNTRY_NAME: 'MISSING_COUNTRY_NAME',
  MISSING_ORGANIZATION_NAME: 'MISSING_ORGANIZATION_NAME',
  MISSING_ORGANIZATION_IDENTIFIER: 'MISSING_ORGANIZATION_IDENTIFIER',
  INVALID_ORGANIZATION_IDENTIFIER: 'INVALID_ORGANIZATION_IDENTIFIER',
  INVALID_GREECE_COUNTRY_CODE: 'INVALID_GREECE_COUNTRY_CODE',
  MISSING_NATURAL_PERSON_NAME: 'MISSING_NATURAL_PERSON_NAME',
  MISSING_SERIAL_NUMBER: 'MISSING_SERIAL_NUMBER',
  INVALID_SERIAL_NUMBER: 'INVALID_SERIAL_NUMBER',
  MISSING_QC_COMPLIANCE: 'MISSING_QC_COMPLIANCE',
  QC_TYPE_MISMATCH: 'QC_TYPE_MISMATCH',
} as const

export type AccessCertificateValidationCode =
  (typeof ACCESS_CERTIFICATE_VALIDATION_CODES)[keyof typeof ACCESS_CERTIFICATE_VALIDATION_CODES]

export type AccessCertificateIssue = AccessCertificateValidationIssue<AccessCertificateValidationCode>

export interface AccessCertificateValidationResult {
  /** `true` when there are no errors; warnings do not affect validity */
  valid: boolean
  errors: AccessCertificateIssue[]
  warnings: AccessCertificateIssue[]
}

const C = ACCESS_CERTIFICATE_VALIDATION_CODES

/**
 * Check a parsed access certificate against the certificate profile of ETSI TS 119 411-8
 * clause 6.6.1 and the profiles it references (ETSI EN 319 412-2 / 412-3 / 412-5).
 *
 * This checks the certificate content only. Signature, chain and revocation checks
 * against the trusted list of access certificate providers are out of scope.
 */
export function validateAccessCertificate(
  accessCertificate: AccessCertificate,
  options: AccessCertificateValidationOptions = {}
): AccessCertificateValidationResult {
  const { certificate } = accessCertificate
  const issues: AccessCertificateIssue[] = []
  const add = (
    severity: AccessCertificateValidationSeverity,
    code: AccessCertificateValidationCode,
    message: string,
    requirement?: string
  ) => issues.push({ severity, code, message, requirement })

  // X.509 basics
  if (certificate.version !== 3) {
    add('error', C.UNSUPPORTED_VERSION, `Expected an X.509 v3 certificate, got v${certificate.version}`)
  }
  if (options.now !== false) {
    const now = options.now ?? new Date()
    if (now < certificate.notBefore) {
      add('error', C.NOT_YET_VALID, `Certificate is not valid before ${certificate.notBefore.toISOString()}`)
    }
    if (now > certificate.notAfter) {
      add('error', C.EXPIRED, `Certificate expired at ${certificate.notAfter.toISOString()}`)
    }
  }
  if (certificate.basicConstraints?.cA) {
    add('error', C.CA_CERTIFICATE, 'An access certificate must be an end-entity certificate (cA is true)')
  }
  if (certificate.keyUsage && !certificate.keyUsage.includes('digitalSignature')) {
    add(
      'warning',
      C.MISSING_DIGITAL_SIGNATURE_KEY_USAGE,
      'Key usage does not include digitalSignature, which is needed to authenticate the wallet-relying party'
    )
  }

  // GEN-6.6.1-03: policy identifiers
  const acceptedOids = new Set(options.acceptedPolicyOids ?? [])
  const hasAcceptedCustomPolicy = certificate.policies.some((p) => acceptedOids.has(p.oid))
  if (accessCertificate.policies.length === 0 && !hasAcceptedCustomPolicy) {
    add(
      'error',
      C.MISSING_POLICY,
      'Certificate does not contain an ETSI TS 119 411-8 certificate policy identifier',
      'GEN-6.6.1-03'
    )
  }
  const policySubjectTypes = new Set(
    accessCertificate.policies.map((p) => ACCESS_CERTIFICATE_POLICY_INFO[p].subjectType)
  )
  if (policySubjectTypes.size > 1) {
    add(
      'error',
      C.CONFLICTING_POLICIES,
      `Certificate policies for both natural and legal persons are present: ${accessCertificate.policies.join(', ')}`,
      'GEN-6.6.1-03'
    )
  }

  // GEN-6.6.1-06: CPS URI
  if (!certificate.policies.some((p) => p.cpsUris.length > 0)) {
    add('error', C.MISSING_CPS_URI, 'Certificate policies do not contain a cpsURI qualifier', 'GEN-6.6.1-06')
  }

  // GEN-6.6.1-07: contact information in the SAN
  const { uris, emails, phoneNumbers } = accessCertificate.contact
  if (uris.length + emails.length + phoneNumbers.length === 0) {
    add(
      'error',
      C.MISSING_CONTACT,
      'Subject alternative name must contain a website (URI), phone number (otherName telephoneNumber) or email address (rfc822Name)',
      'GEN-6.6.1-07'
    )
  }

  // Subject naming
  const subject = certificate.subject
  const subjectType = options.subjectType ?? accessCertificate.subjectType
  if (!subject.commonName) add('error', C.MISSING_COMMON_NAME, 'Subject commonName is missing')
  if (!subject.countryName) add('error', C.MISSING_COUNTRY_NAME, 'Subject countryName is missing')

  if (subjectType === 'legal') {
    if (!subject.organizationName) {
      add('error', C.MISSING_ORGANIZATION_NAME, 'Subject organizationName is missing (ETSI EN 319 412-3)')
    }
    if (!subject.organizationIdentifier) {
      add('error', C.MISSING_ORGANIZATION_IDENTIFIER, 'Subject organizationIdentifier is missing', 'GEN-6.6.1-05')
    } else {
      const identifier = parseSemanticIdentifier(subject.organizationIdentifier)
      if (!identifier) {
        add(
          'error',
          C.INVALID_ORGANIZATION_IDENTIFIER,
          `organizationIdentifier "${subject.organizationIdentifier}" is not encoded as specified in ETSI EN 319 412-1 clause 5.1.4`,
          'GEN-6.6.1-05'
        )
      } else if (identifier.countryCode === 'GR') {
        add(
          'error',
          C.INVALID_GREECE_COUNTRY_CODE,
          'organizationIdentifier must use the country code "EL" for Greece',
          'GEN-6.6.1-05'
        )
      }
    }
  } else if (subjectType === 'natural') {
    if (!(subject.givenName || subject.surname) && !subject.pseudonym) {
      add(
        'error',
        C.MISSING_NATURAL_PERSON_NAME,
        'Subject must contain givenName and/or surname, or a pseudonym (ETSI EN 319 412-2)'
      )
    }
    if (!subject.serialNumber) {
      add(
        'warning',
        C.MISSING_SERIAL_NUMBER,
        'Subject serialNumber is missing; the wallet-relying party has no semantic identifier'
      )
    } else if (!parseSemanticIdentifier(subject.serialNumber)) {
      add(
        'warning',
        C.INVALID_SERIAL_NUMBER,
        `serialNumber "${subject.serialNumber}" is not a semantic identifier as specified in ETSI EN 319 412-1 clause 5.1.3`
      )
    }
  } else {
    add('error', C.UNKNOWN_SUBJECT_TYPE, 'Unable to determine whether the subject is a natural or a legal person')
  }

  // GEN-6.6.1-02: qualified certificates follow ETSI EN 319 412-5
  if (accessCertificate.qualified) {
    if (!certificate.qcStatements?.qcCompliance) {
      add(
        'error',
        C.MISSING_QC_COMPLIANCE,
        'Qualified access certificates must contain the QcCompliance statement (ETSI EN 319 412-5)',
        'GEN-6.6.1-02'
      )
    }
    const expectedType = subjectType === 'natural' ? 'esign' : subjectType === 'legal' ? 'eseal' : undefined
    const qcTypes = certificate.qcStatements?.qcTypes ?? []
    if (expectedType && !qcTypes.includes(expectedType)) {
      add(
        'warning',
        C.QC_TYPE_MISMATCH,
        `Expected QcType ${expectedType} for a ${subjectType} person, found ${qcTypes.length ? qcTypes.join(', ') : 'none'}`,
        'GEN-6.6.1-02'
      )
    }
  }

  const errors = issues.filter((i) => i.severity === 'error')
  return { valid: errors.length === 0, errors, warnings: issues.filter((i) => i.severity === 'warning') }
}

/**
 * Parse and validate an access certificate, throwing when it does not conform.
 *
 * @throws AccessCertificateException with the validation errors as details
 */
export function parseAndValidateAccessCertificate(
  input: CertificateInput,
  options?: AccessCertificateValidationOptions
): AccessCertificate {
  const accessCertificate = parseAccessCertificate(input)
  assertValidAccessCertificate(accessCertificate, options)
  return accessCertificate
}

/**
 * @throws AccessCertificateException with the validation errors as details
 */
export function assertValidAccessCertificate(
  accessCertificate: AccessCertificate,
  options?: AccessCertificateValidationOptions
): void {
  const result = validateAccessCertificate(accessCertificate, options)
  if (!result.valid) {
    throw new AccessCertificateException(
      `Invalid access certificate: ${result.errors.map((e) => e.message).join('; ')}`,
      result.errors
    )
  }
}
