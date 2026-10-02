import { hexDecode } from '@owf/identity-common'
import { AsnConvert, type IAsnParseOptions, OctetString } from '@peculiar/asn1-schema'
import {
  RevokedCertificate as AsnRevokedCertificate,
  AuthorityKeyIdentifier,
  CertificateIssuer,
  CertificateList,
  CRLReason,
  DistributionPointName,
  Extension,
  FreshestCRL,
  GeneralName,
  InvalidityDate,
  IssuingDistributionPoint,
  id_ce_authorityKeyIdentifier,
  id_ce_certificateIssuer,
  id_ce_cRLNumber,
  id_ce_cRLReasons,
  id_ce_deltaCRLIndicator,
  id_ce_freshestCRL,
  id_ce_invalidityDate,
  id_ce_issuerAltName,
  id_ce_issuingDistributionPoint,
  id_pe_authorityInfoAccess,
  KeyIdentifier,
  TBSCertList,
  Time,
  Version,
} from '@peculiar/asn1-x509'
import * as asn1js from 'asn1js'
import { signatureAlgorithmName } from './certificate'
import { CRL_REASONS, type CrlReason } from './constants'
import { parseIssuerCertificate, subjectKeyIdentifierOf, toAsnExtension } from './create'
import { describePublicKey, integerBytesToBigInt, parseDer, toHex, toPositiveIntegerBytes } from './der'
import { type CertificateInput, type CrlInput, PEM_LABELS, toArrayBuffer, toDer, toPem } from './encoding'
import { decodeExtension, toExtensions, urisOf } from './extensions'
import { namesEqual, parseName } from './name'
import { assembleSignedStructure, signatureAlgorithmIdentifier, toSerialNumber, verifyCrlSignature } from './signature'
import type {
  Certificate,
  Crl,
  CrlTemplate,
  DistinguishedName,
  PreparedSignedStructure,
  RevocationCheckOptions,
  RevocationStatus,
  RevokedCertificate,
  SignatureEncoding,
  SignatureVerifier,
  SignOptions,
  X509Extension,
} from './types'
import { X509Exception } from './x509-exception'

const REASON_BY_CODE = new Map<number, CrlReason>(
  Object.entries(CRL_REASONS).map(([name, code]) => [code, name as CrlReason])
)

/** CRL extensions understood by {@link getRevocationStatus} */
const KNOWN_CRL_EXTENSIONS = new Set([
  id_ce_authorityKeyIdentifier,
  id_ce_issuerAltName,
  id_ce_cRLNumber,
  id_ce_deltaCRLIndicator,
  id_ce_issuingDistributionPoint,
  id_ce_freshestCRL,
  id_pe_authorityInfoAccess,
])

/** CRL entry extensions understood by {@link getRevocationStatus} */
const KNOWN_ENTRY_EXTENSIONS = new Set([
  id_ce_cRLReasons,
  id_ce_invalidityDate,
  id_ce_certificateIssuer,
  '2.5.29.23', // holdInstructionCode
])

function decodeInteger(extensions: X509Extension[], oid: string, name: string): bigint | undefined {
  const extension = extensions.find((e) => e.oid === oid)
  if (!extension) return undefined
  const node = parseDer(extension.value)
  const bytes = node instanceof asn1js.Integer ? new Uint8Array(node.valueBlock.valueHexView) : undefined
  if (!bytes || bytes.length === 0 || bytes[0] & 0x80) {
    throw new X509Exception(`Invalid ${name} extension`)
  }
  return integerBytesToBigInt(bytes)
}

function directoryNameOf(names: GeneralName[]): DistinguishedName | undefined {
  const name = names.find((n) => n.directoryName)?.directoryName
  return name ? parseName(name) : undefined
}

function toRevokedCertificates(entries: AsnRevokedCertificate[] | undefined): RevokedCertificate[] {
  let certificateIssuer: DistinguishedName | undefined
  return (entries ?? []).map((entry) => {
    const extensions = toExtensions(entry.crlEntryExtensions)
    const decode = <T>(oid: string, type: new () => T, name: string) => decodeExtension(extensions, oid, type, name)
    const reason = decode(id_ce_cRLReasons, CRLReason, 'reasonCode')
    const invalidity = decode(id_ce_invalidityDate, InvalidityDate, 'invalidityDate')
    const issuer = decode(id_ce_certificateIssuer, CertificateIssuer, 'certificateIssuer')
    // RFC 5280 clause 5.3.3: the certificate issuer applies to this and all following entries
    if (issuer) certificateIssuer = directoryNameOf(issuer)
    return {
      serialNumber: toHex(entry.userCertificate),
      revocationDate: entry.revocationDate.getTime(),
      reason: reason ? REASON_BY_CODE.get(reason.reason) : undefined,
      invalidityDate: invalidity?.value,
      certificateIssuer,
      extensions,
    }
  })
}

export interface ParseCrlOptions extends IAsnParseOptions {
  /**
   * Upper bound for the number of revoked certificate entries, protecting against resource
   * exhaustion by untrusted input. Defaults to 100 000. Ignored when `berOptions.maxNodes`
   * is set explicitly.
   */
  maxEntries?: number
}

/** ASN.1 nodes per CRL entry: SEQUENCE, INTEGER, Time and up to three extensions of four nodes */
const NODES_PER_ENTRY = 16

/**
 * Parse an X.509 certificate revocation list (RFC 5280 clause 5).
 *
 * Parsing does not verify the signature; use {@link verifyCrlSignature} or {@link checkRevocation}.
 *
 * @param input DER bytes, base64 encoded DER, or PEM (`X509 CRL`)
 * @throws X509Exception when the input is not a well-formed CRL or exceeds the size limits
 */
export function parseCrl(input: CrlInput, options: ParseCrlOptions = {}): Crl {
  const der = toDer(input, PEM_LABELS.crl)
  const { maxEntries = 100_000, berOptions } = options
  let crl: CertificateList
  try {
    crl = AsnConvert.parse(toArrayBuffer(der), CertificateList, {
      berOptions: { maxNodes: 1_000 + maxEntries * NODES_PER_ENTRY, ...berOptions },
    })
  } catch (error) {
    throw new X509Exception('Invalid CRL', error)
  }
  if (!crl.tbsCertListRaw) throw new X509Exception('Unable to extract the TBSCertList')

  const tbs = crl.tbsCertList
  const extensions = toExtensions(tbs.crlExtensions)
  const decode = <T>(oid: string, type: new () => T, name: string) => decodeExtension(extensions, oid, type, name)
  const aki = decode(id_ce_authorityKeyIdentifier, AuthorityKeyIdentifier, 'authorityKeyIdentifier')
  const idp = decode(id_ce_issuingDistributionPoint, IssuingDistributionPoint, 'issuingDistributionPoint')
  const freshest = decode(id_ce_freshestCRL, FreshestCRL, 'freshestCRL')

  return {
    der,
    pem: toPem(der, PEM_LABELS.crl),
    version: tbs.version === undefined ? 1 : tbs.version + 1,
    issuer: parseName(tbs.issuer),
    thisUpdate: tbs.thisUpdate.getTime(),
    nextUpdate: tbs.nextUpdate?.getTime(),
    signatureAlgorithm: crl.signatureAlgorithm.algorithm,
    signatureAlgorithmName: signatureAlgorithmName(crl.signatureAlgorithm.algorithm),
    signature: new Uint8Array(crl.signature),
    tbsCertList: new Uint8Array(crl.tbsCertListRaw),
    crlNumber: decodeInteger(extensions, id_ce_cRLNumber, 'cRLNumber'),
    deltaCrlIndicator: decodeInteger(extensions, id_ce_deltaCRLIndicator, 'deltaCRLIndicator'),
    authorityKeyIdentifier: aki?.keyIdentifier ? toHex(aki.keyIdentifier.buffer) : undefined,
    issuingDistributionPoint: idp
      ? {
          distributionPointUris: urisOf(idp.distributionPoint?.fullName),
          onlyContainsUserCerts: idp.onlyContainsUserCerts,
          onlyContainsCACerts: idp.onlyContainsCACerts,
          onlyContainsAttributeCerts: idp.onlyContainsAttributeCerts,
          indirectCRL: idp.indirectCRL,
          onlySomeReasons: idp.onlySomeReasons?.toJSON(),
        }
      : undefined,
    freshestCrl: (freshest ?? []).flatMap((dp) => urisOf(dp.distributionPoint?.fullName)),
    revokedCertificates: toRevokedCertificates(tbs.revokedCertificates),
    extensions,
  }
}

// ============================================================================
// Revocation checking
// ============================================================================

function normalizeSerial(hex: string): string {
  return hex.toLowerCase().replace(/^(00)+(?=..)/, '')
}

function unknown(
  reason: Extract<RevocationStatus, { status: 'unknown' }>['reason'],
  message: string
): RevocationStatus {
  return { status: 'unknown', reason, message }
}

/**
 * Look up the revocation status of `certificate` in `crl`.
 *
 * This does **not** verify the CRL signature; use {@link checkRevocation} unless the CRL
 * has already been verified. The CRL must be issued by the certificate issuer (or be an
 * indirect CRL naming it), must be current, and must cover the certificate. Otherwise the
 * status is `unknown` with the reason, and the caller should find a suitable CRL or fall
 * back to OCSP.
 */
export function getRevocationStatus(
  certificate: Certificate,
  crl: Crl,
  options: RevocationCheckOptions = {}
): RevocationStatus {
  if (crl.deltaCrlIndicator !== undefined) {
    return unknown('delta_crl', 'Delta CRLs can only be used together with their base CRL')
  }
  const unsupported = crl.extensions.find((e) => e.critical && !KNOWN_CRL_EXTENSIONS.has(e.oid))
  if (unsupported) {
    return unknown('unsupported_critical_extension', `Unsupported critical CRL extension ${unsupported.oid}`)
  }

  const idp = crl.issuingDistributionPoint
  const indirect = idp?.indirectCRL ?? false
  if (!indirect) {
    if (!namesEqual(crl.issuer, certificate.issuer)) {
      return unknown('issuer_mismatch', 'The CRL is not issued by the certificate issuer')
    }
    if (
      crl.authorityKeyIdentifier &&
      certificate.authorityKeyIdentifier &&
      crl.authorityKeyIdentifier !== certificate.authorityKeyIdentifier
    ) {
      return unknown('issuer_mismatch', 'The CRL is signed with a different key than the certificate')
    }
  }

  if (options.now !== false) {
    const now = options.now ?? new Date()
    if (now < crl.thisUpdate) {
      return unknown('crl_not_yet_valid', `The CRL is not valid before ${crl.thisUpdate.toISOString()}`)
    }
    if (crl.nextUpdate && now > crl.nextUpdate) {
      return unknown('crl_expired', `The CRL expired at ${crl.nextUpdate.toISOString()}`)
    }
  }

  if (idp) {
    const isCA = certificate.basicConstraints?.cA === true
    if (idp.onlyContainsAttributeCerts) return unknown('out_of_scope', 'The CRL only covers attribute certificates')
    if (idp.onlyContainsCACerts && !isCA) return unknown('out_of_scope', 'The CRL only covers CA certificates')
    if (idp.onlyContainsUserCerts && isCA) return unknown('out_of_scope', 'The CRL only covers end-entity certificates')
    if (
      idp.distributionPointUris.length > 0 &&
      !idp.distributionPointUris.some((uri) => certificate.crlDistributionPoints.includes(uri))
    ) {
      return unknown('out_of_scope', 'The CRL distribution point does not match the certificate')
    }
  }

  const serial = normalizeSerial(certificate.serialNumber)
  const entry = crl.revokedCertificates.find(
    (e) =>
      normalizeSerial(e.serialNumber) === serial &&
      (!indirect || namesEqual(e.certificateIssuer ?? crl.issuer, certificate.issuer))
  )

  if (entry) {
    const unsupportedEntry = entry.extensions.find((e) => e.critical && !KNOWN_ENTRY_EXTENSIONS.has(e.oid))
    if (unsupportedEntry) {
      return unknown(
        'unsupported_critical_extension',
        `Unsupported critical CRL entry extension ${unsupportedEntry.oid}`
      )
    }
    if (entry.reason === 'removeFromCRL') return { status: 'good' }
    return {
      status: 'revoked',
      revocationDate: entry.revocationDate,
      reason: entry.reason,
      invalidityDate: entry.invalidityDate,
    }
  }

  if (idp?.onlySomeReasons) {
    return unknown('out_of_scope', `The CRL only covers the reasons ${idp.onlySomeReasons.join(', ')}`)
  }
  return { status: 'good' }
}

/**
 * Verify the CRL signature against `crlIssuerCertificate`, then look up the revocation
 * status of `certificate` (see {@link getRevocationStatus}).
 *
 * The signature check is delegated to `verifier`; an invalid signature yields `unknown`
 * with reason `invalid_signature`. Fetching the CRL (see `crlDistributionPoints` on the
 * certificate) is up to the caller.
 */
export async function checkRevocation(options: {
  certificate: Certificate
  crl: Crl
  crlIssuerCertificate: Certificate | CertificateInput
  verifier: SignatureVerifier
  now?: Date | false
}): Promise<RevocationStatus> {
  if (!(await verifyCrlSignature(options.crl, options.crlIssuerCertificate, options.verifier))) {
    return unknown('invalid_signature', 'The CRL signature is invalid or not issued by the given certificate')
  }
  return getRevocationStatus(options.certificate, options.crl, { now: options.now })
}

// ============================================================================
// CRL creation
// ============================================================================

function bigintToIntegerBytes(value: bigint | number): Uint8Array {
  const n = BigInt(value)
  if (n < BigInt(0)) throw new X509Exception('CRL numbers must not be negative')
  const hex = n.toString(16)
  const bytes = toPositiveIntegerBytes(hexDecode(hex.length % 2 ? `0${hex}` : hex))
  if (bytes.length > 20) throw new X509Exception('CRL numbers must not be longer than 20 octets')
  return bytes
}

function derExtension(oid: string, value: Uint8Array | ArrayBuffer, critical = false): Extension {
  return new Extension({
    extnID: oid,
    critical,
    extnValue: new OctetString(value instanceof Uint8Array ? toArrayBuffer(value) : value),
  })
}

/**
 * Build the TBSCertList of a v2 CRL. Sign the returned `tbs` bytes with the CRL issuer key
 * and pass the signature to {@link assembleCrl}, or use {@link createCrl} with a signer.
 */
export function prepareCrl(template: CrlTemplate): PreparedSignedStructure {
  if (!(template.nextUpdate > template.thisUpdate)) {
    throw new X509Exception('nextUpdate must be later than thisUpdate')
  }
  const issuer = parseIssuerCertificate(template.issuerCertificate)

  const extensions: Extension[] = []
  const ski = subjectKeyIdentifierOf(issuer)
  if (ski) {
    extensions.push(
      derExtension(
        id_ce_authorityKeyIdentifier,
        AsnConvert.serialize(new AuthorityKeyIdentifier({ keyIdentifier: new KeyIdentifier(ski) }))
      )
    )
  }
  extensions.push(
    derExtension(
      id_ce_cRLNumber,
      new asn1js.Integer({ valueHex: toArrayBuffer(bigintToIntegerBytes(template.crlNumber)) }).toBER()
    )
  )
  const idp = template.issuingDistributionPoint
  if (idp) {
    extensions.push(
      derExtension(
        id_ce_issuingDistributionPoint,
        AsnConvert.serialize(
          new IssuingDistributionPoint({
            distributionPoint: idp.distributionPointUris?.length
              ? new DistributionPointName({
                  fullName: idp.distributionPointUris.map((uri) => new GeneralName({ uniformResourceIdentifier: uri })),
                })
              : undefined,
            onlyContainsUserCerts: idp.onlyContainsUserCerts ?? false,
            onlyContainsCACerts: idp.onlyContainsCACerts ?? false,
          })
        ),
        true
      )
    )
  }
  for (const custom of template.extensions ?? []) extensions.push(toAsnExtension(custom))

  const revoked = (template.revokedCertificates ?? []).map((entry) => {
    const entryExtensions: Extension[] = []
    if (entry.reason && entry.reason !== 'unspecified') {
      entryExtensions.push(
        derExtension(id_ce_cRLReasons, new asn1js.Enumerated({ value: CRL_REASONS[entry.reason] }).toBER())
      )
    }
    if (entry.invalidityDate) {
      entryExtensions.push(
        derExtension(id_ce_invalidityDate, AsnConvert.serialize(new InvalidityDate(entry.invalidityDate)))
      )
    }
    return new AsnRevokedCertificate({
      userCertificate: toSerialNumber(entry.serialNumber),
      revocationDate: new Time(entry.revocationDate),
      crlEntryExtensions: entryExtensions.length > 0 ? entryExtensions : undefined,
    })
  })

  const tbs = new TBSCertList({
    version: Version.v2,
    signature: signatureAlgorithmIdentifier(template.signatureAlgorithm),
    issuer: issuer.tbsCertificate.subject,
    thisUpdate: new Time(template.thisUpdate),
    nextUpdate: new Time(template.nextUpdate),
    revokedCertificates: revoked.length > 0 ? revoked : undefined,
    crlExtensions: extensions,
  })

  return {
    tbs: new Uint8Array(AsnConvert.serialize(tbs)),
    signatureAlgorithm: template.signatureAlgorithm,
    signerPublicKey: describePublicKey(issuer.tbsCertificate.subjectPublicKeyInfo),
  }
}

/** Combine a prepared TBSCertList with the issuer signature. */
export function assembleCrl(
  prepared: PreparedSignedStructure,
  signature: Uint8Array,
  signatureEncoding?: SignatureEncoding
): Crl {
  return parseCrl(assembleSignedStructure(prepared, signature, signatureEncoding))
}

/**
 * Create a v2 CRL. The CRL issuer key is never passed in: the `signer` callback receives the
 * DER encoded TBSCertList and returns the signature.
 */
export async function createCrl(template: CrlTemplate & SignOptions): Promise<Crl> {
  const prepared = prepareCrl(template)
  return assembleCrl(prepared, await template.signer(prepared.tbs), template.signatureEncoding)
}
