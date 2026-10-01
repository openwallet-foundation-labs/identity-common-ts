import { AsnConvert, type IAsnParseOptions } from '@peculiar/asn1-schema'
import {
  AuthorityInfoAccessSyntax,
  AuthorityKeyIdentifier,
  BasicConstraints,
  CertificatePolicies,
  CRLDistributionPoints,
  ExtendedKeyUsage,
  id_ce_authorityKeyIdentifier,
  id_ce_basicConstraints,
  id_ce_certificatePolicies,
  id_ce_cRLDistributionPoints,
  id_ce_extKeyUsage,
  id_ce_keyUsage,
  id_ce_subjectAltName,
  id_ce_subjectKeyIdentifier,
  id_pe_authorityInfoAccess,
  KeyUsage,
  SubjectAlternativeName,
  SubjectKeyIdentifier,
  UserNotice,
  Certificate as X509Certificate,
} from '@peculiar/asn1-x509'
import { QCStatements } from '@peculiar/asn1-x509-qualified'
import {
  ACCESS_METHODS,
  POLICY_QUALIFIERS,
  QC_STATEMENTS,
  SIGNATURE_ALGORITHMS,
  type SignatureAlgorithm,
} from './constants'
import { asn1ToString, describePublicKey, parseDer, toHex } from './der'
import { type CertificateInput, PEM_LABELS, toArrayBuffer, toDer, toPem } from './encoding'
import {
  decodeExtension,
  emptySubjectAlternativeNames,
  toExtensions,
  toSubjectAlternativeNames,
  uriOf,
  urisOf,
} from './extensions'
import { parseName } from './name'
import { parseQcStatements } from './qc-statements'
import type { Certificate, CertificatePolicyInformation } from './types'
import { X509Exception } from './x509-exception'

const SIGNATURE_ALGORITHM_BY_OID = new Map<string, SignatureAlgorithm>(
  Object.entries(SIGNATURE_ALGORITHMS).map(([name, { oid }]) => [oid, name as SignatureAlgorithm])
)

export function signatureAlgorithmName(oid: string): SignatureAlgorithm | undefined {
  return SIGNATURE_ALGORITHM_BY_OID.get(oid)
}

function toPolicies(policies: CertificatePolicies | undefined): CertificatePolicyInformation[] {
  return (policies ?? []).map((policy) => {
    const cpsUris: string[] = []
    const userNotices: string[] = []
    for (const qualifier of policy.policyQualifiers ?? []) {
      if (qualifier.policyQualifierId === POLICY_QUALIFIERS.cps) {
        const uri = asn1ToString(parseDer(qualifier.qualifier))
        if (uri) cpsUris.push(uri)
      } else if (qualifier.policyQualifierId === POLICY_QUALIFIERS.unotice) {
        const notice = AsnConvert.parse(qualifier.qualifier, UserNotice)
        if (notice.explicitText) userNotices.push(notice.explicitText.toString())
      }
    }
    return { oid: policy.policyIdentifier, cpsUris, userNotices }
  })
}

/**
 * Parse an X.509 certificate.
 *
 * Decodes the standard extensions of RFC 5280 plus QCStatements. Parsing does not verify the
 * signature; use {@link verifyCertificateSignature} for that.
 *
 * @param input DER bytes, base64 encoded DER, or PEM
 * @param options Resource limits forwarded to asn1js (`berOptions`)
 * @throws X509Exception when the input is not a well-formed X.509 certificate
 */
export function parseCertificate(input: CertificateInput, options?: IAsnParseOptions): Certificate {
  const der = toDer(input, PEM_LABELS.certificate)

  let certificate: X509Certificate
  try {
    certificate = AsnConvert.parse(toArrayBuffer(der), X509Certificate, options)
  } catch (error) {
    throw new X509Exception('Invalid X.509 certificate', error)
  }
  if (!certificate.tbsCertificateRaw) {
    throw new X509Exception('Unable to extract the TBSCertificate')
  }

  const tbs = certificate.tbsCertificate
  const extensions = toExtensions(tbs.extensions)
  const decode = <T>(oid: string, type: new () => T, name: string) => decodeExtension(extensions, oid, type, name)

  const san = decode(id_ce_subjectAltName, SubjectAlternativeName, 'subjectAltName')
  const keyUsage = decode(id_ce_keyUsage, KeyUsage, 'keyUsage')
  const eku = decode(id_ce_extKeyUsage, ExtendedKeyUsage, 'extKeyUsage')
  const basicConstraints = decode(id_ce_basicConstraints, BasicConstraints, 'basicConstraints')
  const ski = decode(id_ce_subjectKeyIdentifier, SubjectKeyIdentifier, 'subjectKeyIdentifier')
  const aki = decode(id_ce_authorityKeyIdentifier, AuthorityKeyIdentifier, 'authorityKeyIdentifier')
  const crlDps = decode(id_ce_cRLDistributionPoints, CRLDistributionPoints, 'cRLDistributionPoints')
  const aia = decode(id_pe_authorityInfoAccess, AuthorityInfoAccessSyntax, 'authorityInfoAccess') ?? []
  const qcStatements = decode(QC_STATEMENTS.extension, QCStatements, 'qcStatements')
  const accessUrls = (method: string) =>
    aia
      .filter((a) => a.accessMethod === method)
      .map((a) => uriOf(a.accessLocation))
      .filter((u): u is string => u !== undefined)

  return {
    der,
    pem: toPem(der, PEM_LABELS.certificate),
    version: tbs.version + 1,
    serialNumber: toHex(tbs.serialNumber),
    issuer: parseName(tbs.issuer),
    subject: parseName(tbs.subject),
    notBefore: tbs.validity.notBefore.getTime(),
    notAfter: tbs.validity.notAfter.getTime(),
    publicKey: describePublicKey(tbs.subjectPublicKeyInfo),
    signatureAlgorithm: certificate.signatureAlgorithm.algorithm,
    signatureAlgorithmName: signatureAlgorithmName(certificate.signatureAlgorithm.algorithm),
    tbsCertificate: new Uint8Array(certificate.tbsCertificateRaw),
    signature: new Uint8Array(certificate.signatureValue),

    policies: toPolicies(decode(id_ce_certificatePolicies, CertificatePolicies, 'certificatePolicies')),
    subjectAlternativeNames: san ? toSubjectAlternativeNames(san) : emptySubjectAlternativeNames(),
    keyUsage: keyUsage?.toJSON(),
    extendedKeyUsage: eku ? [...eku] : undefined,
    basicConstraints: basicConstraints
      ? { cA: basicConstraints.cA, pathLenConstraint: basicConstraints.pathLenConstraint }
      : undefined,
    subjectKeyIdentifier: ski ? toHex(ski.buffer) : undefined,
    authorityKeyIdentifier: aki?.keyIdentifier ? toHex(aki.keyIdentifier.buffer) : undefined,
    crlDistributionPoints: (crlDps ?? []).flatMap((dp) => urisOf(dp.distributionPoint?.fullName)),
    ocspUrls: accessUrls(ACCESS_METHODS.ocsp),
    caIssuersUrls: accessUrls(ACCESS_METHODS.caIssuers),
    qcStatements: qcStatements ? parseQcStatements(qcStatements) : undefined,

    extensions,
  }
}
