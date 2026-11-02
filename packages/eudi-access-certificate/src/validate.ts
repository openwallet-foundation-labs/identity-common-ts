import { VALIDATION_CODES, type ValidationIssueOf, ValidationIssues, type ValidationResult } from '@owf/identity-common'
import type { CertificateInput } from '@owf/x509'
import { AccessCertificateValidationError } from './access-certificate-error'
import { ACCESS_CERTIFICATE_POLICY_INFO } from './constants'
import { parseAccessCertificate } from './profile'
import { parseSemanticIdentifier } from './semantic-identifier'
import type { AccessCertificate, AccessCertificateValidationOptions } from './types'

export const ACCESS_CERTIFICATE_VALIDATION_CODES = {
  UNSUPPORTED_VERSION: 'unsupported_version',
  /** With `validFrom`, the `notBefore` of the certificate, as context */
  NOT_YET_VALID: VALIDATION_CODES.NOT_YET_VALID,
  /** With `expiredAt`, the `notAfter` of the certificate, as context */
  EXPIRED: VALIDATION_CODES.EXPIRED,
  CA_CERTIFICATE: 'ca_certificate',
  MISSING_DIGITAL_SIGNATURE_KEY_USAGE: 'missing_digital_signature_key_usage',
  MISSING_POLICY: 'missing_policy',
  CONFLICTING_POLICIES: 'conflicting_policies',
  MISSING_CPS_URI: 'missing_cps_uri',
  MISSING_CONTACT: 'missing_contact',
  UNKNOWN_SUBJECT_TYPE: 'unknown_subject_type',
  MISSING_COMMON_NAME: 'missing_common_name',
  MISSING_COUNTRY_NAME: 'missing_country_name',
  /** The `countryName` given to create a certificate is not an ISO 3166-1 alpha-2 code */
  INVALID_COUNTRY_NAME: 'invalid_country_name',
  MISSING_ORGANIZATION_NAME: 'missing_organization_name',
  MISSING_ORGANIZATION_IDENTIFIER: 'missing_organization_identifier',
  INVALID_ORGANIZATION_IDENTIFIER: 'invalid_organization_identifier',
  INVALID_GREECE_COUNTRY_CODE: 'invalid_greece_country_code',
  MISSING_NATURAL_PERSON_NAME: 'missing_natural_person_name',
  MISSING_SERIAL_NUMBER: 'missing_serial_number',
  INVALID_SERIAL_NUMBER: 'invalid_serial_number',
  MISSING_QC_COMPLIANCE: 'missing_qc_compliance',
  QC_TYPE_MISMATCH: 'qc_type_mismatch',
} as const

export type AccessCertificateValidationCode =
  (typeof ACCESS_CERTIFICATE_VALIDATION_CODES)[keyof typeof ACCESS_CERTIFICATE_VALIDATION_CODES]

/**
 * An issue of {@link validateAccessCertificate}. `path` points into the {@link AccessCertificate},
 * e.g. `['certificate', 'subject', 'organizationIdentifier']`, and `requirement` is the
 * requirement identifier of the originating specification, e.g. `GEN-6.6.1-05`.
 */
export type AccessCertificateValidationIssue = ValidationIssueOf<AccessCertificateValidationCode>

/** `valid` when none of the issues is an error; warnings do not affect validity */
export type AccessCertificateValidationResult = ValidationResult<AccessCertificateValidationIssue>

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
  const issues = new ValidationIssues<AccessCertificateValidationCode>()

  // X.509 basics
  if (certificate.version !== 3) {
    issues.add({
      code: C.UNSUPPORTED_VERSION,
      path: ['certificate', 'version'],
      message: `Expected an X.509 v3 certificate, got v${certificate.version}`,
    })
  }
  if (options.now !== false) {
    const now = options.now ?? new Date()
    if (now < certificate.notBefore) {
      issues.add({
        code: C.NOT_YET_VALID,
        path: ['certificate', 'notBefore'],
        message: `Certificate is not valid before ${certificate.notBefore.toISOString()}`,
        context: { validFrom: certificate.notBefore },
      })
    }
    if (now > certificate.notAfter) {
      issues.add({
        code: C.EXPIRED,
        path: ['certificate', 'notAfter'],
        message: `Certificate expired at ${certificate.notAfter.toISOString()}`,
        context: { expiredAt: certificate.notAfter },
      })
    }
  }
  if (certificate.basicConstraints?.cA) {
    issues.add({
      code: C.CA_CERTIFICATE,
      path: ['certificate', 'basicConstraints', 'cA'],
      message: 'An access certificate must be an end-entity certificate (cA is true)',
    })
  }
  if (certificate.keyUsage && !certificate.keyUsage.includes('digitalSignature')) {
    issues.add({
      severity: 'warning',
      code: C.MISSING_DIGITAL_SIGNATURE_KEY_USAGE,
      path: ['certificate', 'keyUsage'],
      message: 'Key usage does not include digitalSignature, which is needed to authenticate the wallet-relying party',
    })
  }

  // GEN-6.6.1-03: policy identifiers
  const acceptedOids = new Set(options.acceptedPolicyOids ?? [])
  const hasAcceptedCustomPolicy = certificate.policies.some((p) => acceptedOids.has(p.oid))
  if (accessCertificate.policies.length === 0 && !hasAcceptedCustomPolicy) {
    issues.add({
      code: C.MISSING_POLICY,
      path: ['certificate', 'policies'],
      message: 'Certificate does not contain an ETSI TS 119 411-8 certificate policy identifier',
      requirement: 'GEN-6.6.1-03',
    })
  }
  const policySubjectTypes = new Set(
    accessCertificate.policies.map((p) => ACCESS_CERTIFICATE_POLICY_INFO[p].subjectType)
  )
  if (policySubjectTypes.size > 1) {
    issues.add({
      code: C.CONFLICTING_POLICIES,
      path: ['policies'],
      message: `Certificate policies for both natural and legal persons are present: ${accessCertificate.policies.join(', ')}`,
      requirement: 'GEN-6.6.1-03',
    })
  }

  // GEN-6.6.1-06: CPS URI
  if (!certificate.policies.some((p) => p.cpsUris.length > 0)) {
    issues.add({
      code: C.MISSING_CPS_URI,
      path: ['certificate', 'policies'],
      message: 'Certificate policies do not contain a cpsURI qualifier',
      requirement: 'GEN-6.6.1-06',
    })
  }

  // GEN-6.6.1-07: contact information in the SAN
  const { uris, emails, phoneNumbers } = accessCertificate.contact
  if (uris.length + emails.length + phoneNumbers.length === 0) {
    issues.add({
      code: C.MISSING_CONTACT,
      path: ['certificate', 'subjectAlternativeNames'],
      message:
        'Subject alternative name must contain a website (URI), phone number (otherName telephoneNumber) or email address (rfc822Name)',
      requirement: 'GEN-6.6.1-07',
    })
  }

  // Subject naming
  const subject = certificate.subject
  const subjectType = options.subjectType ?? accessCertificate.subjectType
  if (!subject.commonName)
    issues.add({
      code: C.MISSING_COMMON_NAME,
      path: ['certificate', 'subject', 'commonName'],
      message: 'Subject commonName is missing',
    })
  if (!subject.countryName)
    issues.add({
      code: C.MISSING_COUNTRY_NAME,
      path: ['certificate', 'subject', 'countryName'],
      message: 'Subject countryName is missing',
    })

  if (subjectType === 'legal') {
    if (!subject.organizationName) {
      issues.add({
        code: C.MISSING_ORGANIZATION_NAME,
        path: ['certificate', 'subject', 'organizationName'],
        message: 'Subject organizationName is missing (ETSI EN 319 412-3)',
      })
    }
    if (!subject.organizationIdentifier) {
      issues.add({
        code: C.MISSING_ORGANIZATION_IDENTIFIER,
        path: ['certificate', 'subject', 'organizationIdentifier'],
        message: 'Subject organizationIdentifier is missing',
        requirement: 'GEN-6.6.1-05',
      })
    } else {
      const identifier = parseSemanticIdentifier(subject.organizationIdentifier)
      if (!identifier) {
        issues.add({
          code: C.INVALID_ORGANIZATION_IDENTIFIER,
          path: ['certificate', 'subject', 'organizationIdentifier'],
          message: `organizationIdentifier "${subject.organizationIdentifier}" is not encoded as specified in ETSI EN 319 412-1 clause 5.1.4`,
          requirement: 'GEN-6.6.1-05',
        })
      } else if (identifier.countryCode === 'GR') {
        issues.add({
          code: C.INVALID_GREECE_COUNTRY_CODE,
          path: ['certificate', 'subject', 'organizationIdentifier'],
          message: 'organizationIdentifier must use the country code "EL" for Greece',
          requirement: 'GEN-6.6.1-05',
        })
      }
    }
  } else if (subjectType === 'natural') {
    if (!(subject.givenName || subject.surname) && !subject.pseudonym) {
      issues.add({
        code: C.MISSING_NATURAL_PERSON_NAME,
        path: ['certificate', 'subject'],
        message: 'Subject must contain givenName and/or surname, or a pseudonym (ETSI EN 319 412-2)',
      })
    }
    if (!subject.serialNumber) {
      issues.add({
        severity: 'warning',
        code: C.MISSING_SERIAL_NUMBER,
        path: ['certificate', 'subject', 'serialNumber'],
        message: 'Subject serialNumber is missing; the wallet-relying party has no semantic identifier',
      })
    } else if (!parseSemanticIdentifier(subject.serialNumber)) {
      issues.add({
        severity: 'warning',
        code: C.INVALID_SERIAL_NUMBER,
        path: ['certificate', 'subject', 'serialNumber'],
        message: `serialNumber "${subject.serialNumber}" is not a semantic identifier as specified in ETSI EN 319 412-1 clause 5.1.3`,
      })
    }
  } else {
    issues.add({
      code: C.UNKNOWN_SUBJECT_TYPE,
      path: ['subjectType'],
      message: 'Unable to determine whether the subject is a natural or a legal person',
    })
  }

  // GEN-6.6.1-02: qualified certificates follow ETSI EN 319 412-5
  if (accessCertificate.qualified) {
    if (!certificate.qcStatements?.qcCompliance) {
      issues.add({
        code: C.MISSING_QC_COMPLIANCE,
        path: ['certificate', 'qcStatements', 'qcCompliance'],
        message: 'Qualified access certificates must contain the QcCompliance statement (ETSI EN 319 412-5)',
        requirement: 'GEN-6.6.1-02',
      })
    }
    const expectedType = subjectType === 'natural' ? 'esign' : subjectType === 'legal' ? 'eseal' : undefined
    const qcTypes = certificate.qcStatements?.qcTypes ?? []
    if (expectedType && !qcTypes.includes(expectedType)) {
      issues.add({
        severity: 'warning',
        code: C.QC_TYPE_MISMATCH,
        path: ['certificate', 'qcStatements', 'qcTypes'],
        message: `Expected QcType ${expectedType} for a ${subjectType} person, found ${qcTypes.length ? qcTypes.join(', ') : 'none'}`,
        requirement: 'GEN-6.6.1-02',
      })
    }
  }

  return issues.result()
}

/**
 * Parse and validate an access certificate, throwing when it does not conform.
 *
 * @throws AccessCertificateValidationError with the issues of the validation
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
 * @throws AccessCertificateValidationError with the issues of the validation
 */
export function assertValidAccessCertificate(
  accessCertificate: AccessCertificate,
  options?: AccessCertificateValidationOptions
): void {
  const result = validateAccessCertificate(accessCertificate, options)
  if (!result.valid) throw new AccessCertificateValidationError('Invalid access certificate', result.issues)
}
