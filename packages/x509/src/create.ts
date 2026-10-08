import { AsnConvert, OctetString } from '@peculiar/asn1-schema'
import {
  AccessDescription,
  AuthorityInfoAccessSyntax,
  AuthorityKeyIdentifier,
  BasicConstraints,
  CertificatePolicies,
  CRLDistributionPoints,
  DistributionPoint,
  DistributionPointName,
  ExtendedKeyUsage,
  Extension,
  Extensions,
  GeneralName,
  id_ce_authorityKeyIdentifier,
  id_ce_basicConstraints,
  id_ce_certificatePolicies,
  id_ce_cRLDistributionPoints,
  id_ce_extKeyUsage,
  id_ce_keyUsage,
  id_ce_subjectAltName,
  id_ce_subjectKeyIdentifier,
  id_pe_authorityInfoAccess,
  KeyIdentifier,
  KeyUsage,
  KeyUsageFlags,
  type KeyUsageType,
  OtherName,
  PolicyInformation,
  PolicyQualifierInfo,
  SubjectAlternativeName,
  SubjectKeyIdentifier,
  SubjectPublicKeyInfo,
  TBSCertificate,
  Validity,
  Version,
  Certificate as X509Certificate,
} from '@peculiar/asn1-x509'
import * as asn1js from 'asn1js'
import { parseCertificate } from './certificate'
import { ACCESS_METHODS, POLICY_QUALIFIERS, QC_STATEMENTS } from './constants'
import { describePublicKey, publicJwkToSpki } from './der'
import { type CertificateInput, PEM_LABELS, toArrayBuffer, toDer } from './encoding'
import { buildName } from './name'
import { toQcStatements } from './qc-statements'
import { assembleSignedStructure, signatureAlgorithmIdentifier, toSerialNumber } from './signature'
import type {
  Certificate,
  CertificateTemplate,
  PreparedSignedStructure,
  SignatureEncoding,
  SignOptions,
  X509Extension,
} from './types'
import { X509Exception } from './x509-exception'

function extension(extnID: string, value: unknown, critical = false): Extension {
  return new Extension({ extnID, critical, extnValue: new OctetString(AsnConvert.serialize(value)) })
}

export function keyUsageFlags(usages: KeyUsageType[]): number {
  return usages.reduce((flags, usage) => flags | KeyUsageFlags[usage === 'crlSign' ? 'cRLSign' : usage], 0)
}

/** Parse an issuer certificate into its ASN.1 form. */
export function parseIssuerCertificate(input: CertificateInput): X509Certificate {
  try {
    return AsnConvert.parse(toArrayBuffer(toDer(input, PEM_LABELS.certificate)), X509Certificate)
  } catch (error) {
    throw new X509Exception('Invalid issuer certificate', error)
  }
}

/** The subject key identifier of an ASN.1 certificate, if present. */
export function subjectKeyIdentifierOf(certificate: X509Certificate): ArrayBuffer | undefined {
  const ski = certificate.tbsCertificate.extensions?.find((e) => e.extnID === id_ce_subjectKeyIdentifier)
  return ski ? AsnConvert.parse(ski.extnValue.buffer, SubjectKeyIdentifier).buffer : undefined
}

/**
 * Encode an otherName whose value is a PrintableString (or UTF8String for non-printable
 * values), e.g. an `id-at-telephoneNumber` subject alternative name.
 */
export function stringOtherName(typeId: string, value: string): { typeId: string; value: Uint8Array } {
  const printable = /^[A-Za-z0-9 '()+,\-./:=?]*$/.test(value)
  const encoded = printable ? new asn1js.PrintableString({ value }) : new asn1js.Utf8String({ value })
  return { typeId, value: new Uint8Array(encoded.toBER()) }
}

/**
 * Build the TBSCertificate for a certificate template.
 *
 * Sign the returned `tbs` bytes with the issuer key wherever that key lives and pass the
 * signature to {@link assembleCertificate}. {@link createCertificate} wraps both steps
 * around a signer callback.
 */
export async function prepareCertificate(template: CertificateTemplate): Promise<PreparedSignedStructure> {
  if (!(template.notAfter > template.notBefore)) {
    throw new X509Exception('notAfter must be later than notBefore')
  }

  const spkiDer =
    template.subjectPublicKey instanceof Uint8Array
      ? template.subjectPublicKey
      : publicJwkToSpki(template.subjectPublicKey)
  let subjectPublicKeyInfo: SubjectPublicKeyInfo
  try {
    subjectPublicKeyInfo = AsnConvert.parse(toArrayBuffer(spkiDer), SubjectPublicKeyInfo)
  } catch (error) {
    throw new X509Exception('Invalid subject public key', error)
  }

  const issuer = template.issuerCertificate ? parseIssuerCertificate(template.issuerCertificate) : undefined
  const subject = buildName(template.subject)
  if (subject.length === 0) throw new X509Exception('The subject must not be empty')

  const extensions: Extension[] = []
  const basicConstraints = template.basicConstraints ?? { cA: false }
  extensions.push(extension(id_ce_basicConstraints, new BasicConstraints(basicConstraints), true))

  const keyUsage = template.keyUsage ?? (basicConstraints.cA ? ['keyCertSign', 'crlSign'] : ['digitalSignature'])
  if (keyUsage.length > 0) {
    extensions.push(extension(id_ce_keyUsage, new KeyUsage(keyUsageFlags(keyUsage)), true))
  }

  if (template.extendedKeyUsage?.length) {
    extensions.push(extension(id_ce_extKeyUsage, new ExtendedKeyUsage(template.extendedKeyUsage)))
  }

  if (template.certificatePolicies?.length) {
    extensions.push(
      extension(
        id_ce_certificatePolicies,
        new CertificatePolicies(
          template.certificatePolicies.map(
            (policy) =>
              new PolicyInformation({
                policyIdentifier: policy.oid,
                policyQualifiers: policy.cpsUris?.length
                  ? policy.cpsUris.map(
                      (uri) =>
                        new PolicyQualifierInfo({
                          policyQualifierId: POLICY_QUALIFIERS.cps,
                          qualifier: new asn1js.IA5String({ value: uri }).toBER(),
                        })
                    )
                  : undefined,
              })
          )
        )
      )
    )
  }

  const san = template.subjectAlternativeNames
  const generalNames = [
    ...(san?.dnsNames ?? []).map((dNSName) => new GeneralName({ dNSName })),
    ...(san?.uris ?? []).map((uniformResourceIdentifier) => new GeneralName({ uniformResourceIdentifier })),
    ...(san?.emails ?? []).map((rfc822Name) => new GeneralName({ rfc822Name })),
    ...(san?.otherNames ?? []).map(
      (o) => new GeneralName({ otherName: new OtherName({ typeId: o.typeId, value: toArrayBuffer(o.value) }) })
    ),
  ]
  if (generalNames.length > 0) {
    extensions.push(extension(id_ce_subjectAltName, new SubjectAlternativeName(generalNames)))
  }

  let subjectKeyIdentifier: ArrayBuffer | undefined
  if (template.hasher) {
    // RFC 7093 method 1: leftmost 160 bits of the SHA-256 hash of the subjectPublicKey
    const hash = await template.hasher(subjectPublicKeyInfo.subjectPublicKey, 'sha-256')
    subjectKeyIdentifier = toArrayBuffer(hash.slice(0, 20))
    extensions.push(extension(id_ce_subjectKeyIdentifier, new SubjectKeyIdentifier(subjectKeyIdentifier)))
  }

  const authorityKeyIdentifier = issuer ? subjectKeyIdentifierOf(issuer) : subjectKeyIdentifier
  if (authorityKeyIdentifier) {
    extensions.push(
      extension(
        id_ce_authorityKeyIdentifier,
        new AuthorityKeyIdentifier({ keyIdentifier: new KeyIdentifier(authorityKeyIdentifier) })
      )
    )
  }

  if (template.crlDistributionPoints?.length) {
    extensions.push(
      extension(
        id_ce_cRLDistributionPoints,
        new CRLDistributionPoints(
          template.crlDistributionPoints.map(
            (uri) =>
              new DistributionPoint({
                distributionPoint: new DistributionPointName({
                  fullName: [new GeneralName({ uniformResourceIdentifier: uri })],
                }),
              })
          )
        )
      )
    )
  }

  const accessDescriptions = [
    ...(template.ocspUrls ?? []).map((uri) => [ACCESS_METHODS.ocsp, uri] as const),
    ...(template.caIssuersUrls ?? []).map((uri) => [ACCESS_METHODS.caIssuers, uri] as const),
  ].map(
    ([accessMethod, uri]) =>
      new AccessDescription({ accessMethod, accessLocation: new GeneralName({ uniformResourceIdentifier: uri }) })
  )
  if (accessDescriptions.length > 0) {
    extensions.push(extension(id_pe_authorityInfoAccess, new AuthorityInfoAccessSyntax(accessDescriptions)))
  }

  if (template.qcStatements) {
    const qcStatements = toQcStatements({ ...template.qcStatements, qcTypes: template.qcStatements.qcTypes ?? [] })
    extensions.push(extension(QC_STATEMENTS.extension, qcStatements))
  }

  for (const custom of template.extensions ?? []) {
    extensions.push(toAsnExtension(custom))
  }
  const seen = new Set<string>()
  for (const { extnID } of extensions) {
    if (seen.has(extnID)) throw new X509Exception(`Duplicate extension ${extnID}`)
    seen.add(extnID)
  }

  const tbs = new TBSCertificate({
    version: Version.v3,
    serialNumber: toSerialNumber(template.serialNumber),
    signature: signatureAlgorithmIdentifier(template.signatureAlgorithm),
    issuer: issuer ? issuer.tbsCertificate.subject : subject,
    validity: new Validity({ notBefore: template.notBefore, notAfter: template.notAfter }),
    subject,
    subjectPublicKeyInfo,
    extensions: new Extensions(extensions),
  })

  return {
    tbs: new Uint8Array(AsnConvert.serialize(tbs)),
    signatureAlgorithm: template.signatureAlgorithm,
    signerPublicKey: describePublicKey(issuer ? issuer.tbsCertificate.subjectPublicKeyInfo : subjectPublicKeyInfo),
  }
}

export function toAsnExtension(extension: X509Extension): Extension {
  return new Extension({
    extnID: extension.oid,
    critical: extension.critical,
    extnValue: new OctetString(toArrayBuffer(extension.value)),
  })
}

/**
 * Combine a prepared TBSCertificate with the issuer signature.
 *
 * @param signatureEncoding Encoding of ECDSA signatures; WebCrypto produces `ieee-p1363` (default)
 */
export function assembleCertificate(
  prepared: PreparedSignedStructure,
  signature: Uint8Array,
  signatureEncoding?: SignatureEncoding
): Certificate {
  return parseCertificate(assembleSignedStructure(prepared, signature, signatureEncoding))
}

/**
 * Create an X.509 v3 certificate.
 *
 * The issuer key is never passed in: the `signer` callback receives the DER encoded
 * TBSCertificate and returns the signature, so the key can stay in WebCrypto, a KMS or an
 * HSM. Only the public key of the subject is needed; a JWK with private key material is
 * rejected.
 */
export async function createCertificate(template: CertificateTemplate & SignOptions): Promise<Certificate> {
  const prepared = await prepareCertificate(template)
  const signature = await template.signer(prepared.tbs)
  return assembleCertificate(prepared, signature, template.signatureEncoding)
}
