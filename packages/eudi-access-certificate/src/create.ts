import {
  ATTRIBUTE_TYPES,
  assembleCertificate,
  type CertificateTemplate,
  type NameAttributeInput,
  prepareCertificate,
  type SignatureEncoding,
  stringOtherName,
} from '@owf/x509'
import { AccessCertificateException } from './access-certificate-exception'
import { ACCESS_CERTIFICATE_POLICIES, ACCESS_CERTIFICATE_POLICY_INFO } from './constants'
import { toAccessCertificate } from './profile'
import { parseSemanticIdentifier } from './semantic-identifier'
import type {
  AccessCertificate,
  CreateAccessCertificateOptions,
  LegalPersonAccessCertificateOptions,
  NaturalPersonSubjectInput,
  PrepareAccessCertificateOptions,
  PreparedAccessCertificate,
} from './types'
import { validateAccessCertificate } from './validate'

function isLegalPerson(options: PrepareAccessCertificateOptions): options is LegalPersonAccessCertificateOptions {
  return ACCESS_CERTIFICATE_POLICY_INFO[options.policy]?.subjectType === 'legal'
}

function subjectAttributes(options: PrepareAccessCertificateOptions): NameAttributeInput[] {
  const ous = (options.subject.organizationalUnitNames ?? []).map(
    (ou): NameAttributeInput => ['organizationalUnitName', ou]
  )
  if (isLegalPerson(options)) {
    const s = options.subject
    return [
      ['countryName', s.countryName],
      ['stateOrProvinceName', s.stateOrProvinceName],
      ['localityName', s.localityName],
      ['organizationName', s.organizationName],
      ...ous,
      ['organizationIdentifier', s.organizationIdentifier],
      ['commonName', s.commonName],
    ]
  }
  const s = options.subject as NaturalPersonSubjectInput
  return [
    ['countryName', s.countryName],
    ...ous,
    ['givenName', s.givenName],
    ['surname', s.surname],
    ['pseudonym', s.pseudonym],
    ['serialNumber', s.serialNumber],
    ['commonName', s.commonName],
  ]
}

function assertInput(options: PrepareAccessCertificateOptions): void {
  if (!ACCESS_CERTIFICATE_POLICIES[options.policy]) {
    throw new AccessCertificateException(`Unknown access certificate policy: ${options.policy}`)
  }
  if (!options.cpsUri) {
    throw new AccessCertificateException('cpsUri is required (GEN-6.6.1-06)')
  }
  const { uris = [], emails = [], phoneNumbers = [] } = options.contact
  if (uris.length + emails.length + phoneNumbers.length === 0) {
    throw new AccessCertificateException(
      'At least one contact website, email address or phone number is required (GEN-6.6.1-07)'
    )
  }
  if (!/^[A-Z]{2}$/.test(options.subject.countryName)) {
    throw new AccessCertificateException('countryName must be an ISO 3166-1 alpha-2 country code')
  }
  if (isLegalPerson(options)) {
    const identifier = parseSemanticIdentifier(options.subject.organizationIdentifier)
    if (!identifier) {
      throw new AccessCertificateException(
        'organizationIdentifier must be encoded as specified in ETSI EN 319 412-1 clause 5.1.4 (GEN-6.6.1-05)'
      )
    }
    if (identifier.countryCode === 'GR') {
      throw new AccessCertificateException('organizationIdentifier must use the country code "EL" for Greece')
    }
  }
}

/** Map access certificate options to a generic `@owf/x509` certificate template. */
export function toCertificateTemplate(options: PrepareAccessCertificateOptions): CertificateTemplate {
  assertInput(options)
  const policyInfo = ACCESS_CERTIFICATE_POLICY_INFO[options.policy]
  const cpsUris = [options.cpsUri]
  const { uris = [], emails = [], phoneNumbers = [] } = options.contact

  return {
    subject: subjectAttributes(options),
    subjectPublicKey: options.subjectPublicKey,
    issuerCertificate: options.issuerCertificate,
    serialNumber: options.serialNumber,
    notBefore: options.notBefore,
    notAfter: options.notAfter,
    signatureAlgorithm: options.signatureAlgorithm,
    basicConstraints: { cA: false },
    keyUsage: options.keyUsage ?? ['digitalSignature'],
    extendedKeyUsage: options.extendedKeyUsage,
    certificatePolicies: [
      { oid: ACCESS_CERTIFICATE_POLICIES[options.policy], cpsUris },
      ...(options.additionalPolicyOids ?? []).map((oid) => ({ oid, cpsUris })),
    ],
    subjectAlternativeNames: {
      dnsNames: options.dnsNames,
      uris,
      emails,
      otherNames: phoneNumbers.map((phone) => stringOtherName(ATTRIBUTE_TYPES.telephoneNumber, phone)),
    },
    crlDistributionPoints: options.crlDistributionPoints,
    ocspUrls: options.ocspUrls,
    caIssuersUrls: options.caIssuersUrls,
    qcStatements: policyInfo.qualified
      ? { ...options.qcStatements, qcTypes: [policyInfo.subjectType === 'legal' ? 'eseal' : 'esign'] }
      : undefined,
    hasher: options.hasher,
  }
}

/**
 * Build the TBSCertificate of an access certificate per ETSI TS 119 411-8 clause 6.6.1.
 *
 * Sign the returned `tbs` bytes with the issuing CA key wherever that key lives and pass the
 * signature to {@link assembleAccessCertificate}. {@link createAccessCertificate} wraps both
 * steps around a signer callback.
 */
export function prepareAccessCertificate(options: PrepareAccessCertificateOptions): Promise<PreparedAccessCertificate> {
  return prepareCertificate(toCertificateTemplate(options))
}

/**
 * Combine a prepared TBSCertificate with the signature of the issuing CA.
 *
 * @param signatureEncoding Encoding of ECDSA signatures; WebCrypto produces `ieee-p1363` (default)
 */
export function assembleAccessCertificate(
  prepared: PreparedAccessCertificate,
  signature: Uint8Array,
  signatureEncoding?: SignatureEncoding
): AccessCertificate {
  return toAccessCertificate(assembleCertificate(prepared, signature, signatureEncoding))
}

/**
 * Create a wallet-relying party access certificate per ETSI TS 119 411-8.
 *
 * The issuing CA key is never passed in: the `signer` callback receives the DER encoded
 * TBSCertificate and returns the signature, so the key can stay in WebCrypto, a KMS or an HSM.
 * Likewise only the public key of the wallet-relying party is needed; a JWK that contains
 * private key material is rejected.
 *
 * @throws AccessCertificateException when the input or the resulting certificate does not
 * satisfy the certificate profile
 */
export async function createAccessCertificate(options: CreateAccessCertificateOptions): Promise<AccessCertificate> {
  const prepared = await prepareAccessCertificate(options)
  const signature = await options.signer(prepared.tbs)
  const accessCertificate = assembleAccessCertificate(prepared, signature, options.signatureEncoding)

  const result = validateAccessCertificate(accessCertificate, { now: false })
  if (!result.valid) {
    throw new AccessCertificateException(
      `Created access certificate does not conform: ${result.errors.map((e) => e.message).join('; ')}`,
      result.errors
    )
  }
  return accessCertificate
}
