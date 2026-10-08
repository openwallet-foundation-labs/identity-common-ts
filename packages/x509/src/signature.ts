import { concatBytes, hexDecode } from '@owf/identity-common'
import { AsnConvert } from '@peculiar/asn1-schema'
import { AlgorithmIdentifier } from '@peculiar/asn1-x509'
import * as asn1js from 'asn1js'
import { parseCertificate } from './certificate'
import { SIGNATURE_ALGORITHMS, type SignatureAlgorithm } from './constants'
import { curveCoordinateLength, derTlv, ecdsaDerToP1363, ecdsaP1363ToDer, toPositiveIntegerBytes } from './der'
import { type CertificateInput, toArrayBuffer } from './encoding'
import { namesEqual } from './name'
import type {
  Certificate,
  Crl,
  ParsedPublicKey,
  PreparedSignedStructure,
  SignatureEncoding,
  SignatureVerifier,
} from './types'
import { X509Exception } from './x509-exception'

/** AlgorithmIdentifier for a supported signature algorithm (RFC 3279, RFC 5758). */
export function signatureAlgorithmIdentifier(name: SignatureAlgorithm): AlgorithmIdentifier {
  const algorithm = SIGNATURE_ALGORITHMS[name]
  if (!algorithm) throw new X509Exception(`Unsupported signature algorithm: ${name}`)
  return new AlgorithmIdentifier({
    algorithm: algorithm.oid,
    // RSA PKCS#1 v1.5 algorithms carry NULL parameters, ECDSA ones none
    parameters: algorithm.family === 'rsa' ? new asn1js.Null().toBER() : undefined,
  })
}

/** Normalize a serial number to positive DER INTEGER content (RFC 5280 clause 4.1.2.2). */
export function toSerialNumber(serialNumber: Uint8Array | string): ArrayBuffer {
  const bytes = typeof serialNumber === 'string' ? hexDecode(serialNumber.replace(/^0x/i, '')) : serialNumber
  const positive = toPositiveIntegerBytes(bytes)
  if (positive.length === 0 || positive.every((b) => b === 0)) {
    throw new X509Exception('Serial number must be a positive integer')
  }
  if (positive.length > 20) {
    throw new X509Exception('Serial number must not be longer than 20 octets (RFC 5280 clause 4.1.2.2)')
  }
  return toArrayBuffer(positive)
}

/**
 * Combine prepared to-be-signed bytes with their signature into the DER encoding of the
 * signed structure: `SEQUENCE { tbs, signatureAlgorithm, BIT STRING signature }`.
 */
export function assembleSignedStructure(
  prepared: PreparedSignedStructure,
  signature: Uint8Array,
  signatureEncoding: SignatureEncoding = 'ieee-p1363'
): Uint8Array {
  const algorithm = SIGNATURE_ALGORITHMS[prepared.signatureAlgorithm]
  let signatureDer = signature
  if (algorithm.family === 'ecdsa' && signatureEncoding === 'ieee-p1363') {
    const coordinateLength = curveCoordinateLength(prepared.signerPublicKey.namedCurve)
    if (!coordinateLength) {
      throw new X509Exception('Unable to determine the curve of the signer key for ECDSA encoding')
    }
    signatureDer = ecdsaP1363ToDer(signature, coordinateLength)
  }
  const algorithmIdentifier = new Uint8Array(
    AsnConvert.serialize(signatureAlgorithmIdentifier(prepared.signatureAlgorithm))
  )
  return derTlv(
    0x30,
    concatBytes(prepared.tbs, algorithmIdentifier, derTlv(0x03, concatBytes(new Uint8Array([0]), signatureDer)))
  )
}

async function verifySignature(
  signed: { signature: Uint8Array; signatureAlgorithm: string; signatureAlgorithmName?: SignatureAlgorithm },
  data: Uint8Array,
  publicKey: ParsedPublicKey,
  verifier: SignatureVerifier
): Promise<boolean> {
  let signatureP1363 = signed.signature
  if (signed.signatureAlgorithmName && SIGNATURE_ALGORITHMS[signed.signatureAlgorithmName].family === 'ecdsa') {
    const coordinateLength = curveCoordinateLength(publicKey.namedCurve)
    if (!coordinateLength) return false
    try {
      signatureP1363 = ecdsaDerToP1363(signed.signature, coordinateLength)
    } catch {
      return false
    }
  }
  return verifier({
    data,
    signature: signed.signature,
    signatureP1363,
    signatureAlgorithm: signed.signatureAlgorithm,
    signatureAlgorithmName: signed.signatureAlgorithmName,
    publicKey,
  })
}

function toCertificate(input: Certificate | CertificateInput): Certificate {
  return typeof input === 'object' && 'tbsCertificate' in input ? input : parseCertificate(input)
}

/**
 * Verify that `certificate` was signed by the key of `issuerCertificate`.
 *
 * The issuer name and, when both are present, the authority / subject key identifiers must
 * match. The cryptographic check is delegated to `verifier`, so no global crypto is needed:
 * with WebCrypto, import `publicKey.jwk` and verify `signatureP1363` over `data`.
 *
 * This checks a single link, not a path to a trust anchor.
 */
export async function verifyCertificateSignature(
  certificate: Certificate | CertificateInput,
  issuerCertificate: Certificate | CertificateInput,
  verifier: SignatureVerifier
): Promise<boolean> {
  const cert = toCertificate(certificate)
  const issuer = toCertificate(issuerCertificate)
  if (!namesEqual(cert.issuer, issuer.subject)) return false
  if (
    cert.authorityKeyIdentifier &&
    issuer.subjectKeyIdentifier &&
    cert.authorityKeyIdentifier !== issuer.subjectKeyIdentifier
  ) {
    return false
  }
  return verifySignature(cert, cert.tbsCertificate, issuer.publicKey, verifier)
}

/**
 * Verify that `crl` was signed by `issuerCertificate`.
 *
 * The CRL issuer name and, when both are present, the key identifiers must match, and the
 * issuer key usage (if present) must allow cRLSign (RFC 5280 clause 6.3.3).
 */
export async function verifyCrlSignature(
  crl: Crl,
  issuerCertificate: Certificate | CertificateInput,
  verifier: SignatureVerifier
): Promise<boolean> {
  const issuer = toCertificate(issuerCertificate)
  if (!namesEqual(crl.issuer, issuer.subject)) return false
  if (
    crl.authorityKeyIdentifier &&
    issuer.subjectKeyIdentifier &&
    crl.authorityKeyIdentifier !== issuer.subjectKeyIdentifier
  ) {
    return false
  }
  if (issuer.keyUsage && !issuer.keyUsage.includes('crlSign')) return false
  return verifySignature(crl, crl.tbsCertList, issuer.publicKey, verifier)
}
