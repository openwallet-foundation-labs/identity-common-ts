import { base64, base64url, compareBytes } from '@owf/identity-common'
import { type Certificate, parseCertificate, type SignatureVerifier, verifyCertificateSignature } from '@owf/x509'
import { decodeBinaryText, errorMessage, isRecord } from './input'
import { InspectionError, type SignatureCheck, type SignatureResult } from './inspection'

// Signatures are verified with a Web Crypto implementation the caller passes, e.g.
// `globalThis.crypto` of a browser or of Node.js

/** A public key to verify with */
export interface VerificationKey {
  /** How to name the key to the user, e.g. the subject of its certificate */
  description: string
  /** A JWK, or a DER SubjectPublicKeyInfo for keys without a JWK form */
  key: JsonWebKey | Uint8Array
  /** The certificate the key is from */
  certificate?: Certificate
}

interface WebCryptoAlgorithm {
  hash?: string
  sign: 'ECDSA' | 'RSASSA-PKCS1-v1_5' | 'RSA-PSS' | 'Ed25519'
}

/** The Web Crypto algorithm of a JWS alg, which is also the name @owf/x509 gives a certificate signature */
function webCryptoAlgorithm(alg: string): WebCryptoAlgorithm | undefined {
  const match = /^(ES|RS|PS)(256|384|512)$/.exec(alg)
  if (match) {
    const hash = `SHA-${match[2]}`
    if (match[1] === 'ES') return { sign: 'ECDSA', hash }
    return { sign: match[1] === 'RS' ? 'RSASSA-PKCS1-v1_5' : 'RSA-PSS', hash }
  }
  if (alg === 'EdDSA' || alg === 'Ed25519') return { sign: 'Ed25519' }
  return undefined
}

const CURVES: Record<string, string> = { ES256: 'P-256', ES384: 'P-384', ES512: 'P-521' }

async function importKey(
  crypto: Crypto,
  key: VerificationKey,
  alg: string,
  algorithm: WebCryptoAlgorithm
): Promise<CryptoKey | undefined> {
  const params =
    algorithm.sign === 'ECDSA'
      ? { name: 'ECDSA', namedCurve: (!(key.key instanceof Uint8Array) && key.key.crv) || CURVES[alg] }
      : algorithm.sign === 'Ed25519'
        ? { name: 'Ed25519' }
        : { name: algorithm.sign, hash: algorithm.hash }
  try {
    if (key.key instanceof Uint8Array) {
      return await crypto.subtle.importKey('spki', Uint8Array.from(key.key), params, false, ['verify'])
    }
    // alg, use and key_ops of the JWK would make the import fail where they do not match
    const { kty, crv, x, y, n, e } = key.key
    return await crypto.subtle.importKey('jwk', { kty, crv, x, y, n, e }, params, false, ['verify'])
  } catch {
    // A key of another type or curve
    return undefined
  }
}

async function verifyWith(
  crypto: Crypto,
  key: VerificationKey,
  alg: string,
  data: Uint8Array,
  signature: Uint8Array
): Promise<boolean> {
  const algorithm = webCryptoAlgorithm(alg)
  if (!algorithm) throw new InspectionError(`The algorithm ${alg} is not supported`)
  const cryptoKey = await importKey(crypto, key, alg, algorithm)
  if (!cryptoKey) return false
  const params =
    algorithm.sign === 'RSA-PSS'
      ? { name: 'RSA-PSS', saltLength: Number(alg.slice(2)) / 8 }
      : { name: algorithm.sign, hash: algorithm.hash }
  return crypto.subtle.verify(params, cryptoKey, Uint8Array.from(signature), Uint8Array.from(data))
}

export const certificateName = (certificate: Certificate) =>
  certificate.subject.commonName ?? certificate.subject.organizationName ?? `serial ${certificate.serialNumber}`

export function certificateKey(certificate: Certificate): VerificationKey {
  return {
    description: `certificate ${certificateName(certificate)}`,
    key: certificate.publicKey.jwk ?? certificate.publicKey.spki,
    certificate,
  }
}

function parseCertificateOrThrow(input: string | Uint8Array): Certificate {
  try {
    return parseCertificate(input)
  } catch (error) {
    throw new InspectionError(`The certificate cannot be parsed: ${errorMessage(error)}`)
  }
}

function jwkKey(value: unknown): VerificationKey {
  if (!isRecord(value) || typeof value.kty !== 'string') throw new InspectionError('A JWK needs a kty')
  return { description: `JWK${typeof value.kid === 'string' ? ` ${value.kid}` : ''}`, key: value as JsonWebKey }
}

/**
 * The PEM blocks of the text. Each part after a BEGIN line is searched for its END line, as a
 * regular expression over the whole text could take long on many BEGIN lines without an END.
 */
function pemBlocks(text: string): { label: string; body: string }[] {
  const blocks: { label: string; body: string }[] = []
  for (const part of text.split('-----BEGIN ').slice(1)) {
    const labelEnd = part.indexOf('-----')
    const label = part.slice(0, labelEnd)
    if (labelEnd < 0 || !/^[A-Z ]+$/.test(label)) continue
    const end = part.indexOf(`-----END ${label}-----`, labelEnd + 5)
    if (end >= 0) blocks.push({ label, body: part.slice(labelEnd + 5, end) })
  }
  return blocks
}

/**
 * Read the keys of a JWK, a JWK Set, PEM certificates or public keys, or a certificate as
 * base64 or hex.
 *
 * @throws InspectionError when the text is none of them
 */
export function parseKeys(text: string): VerificationKey[] {
  const trimmed = text.trim()
  if (trimmed.startsWith('{')) {
    let value: unknown
    try {
      value = JSON.parse(trimmed)
    } catch (error) {
      throw new InspectionError(`The key is not valid JSON: ${errorMessage(error)}`)
    }
    if (isRecord(value) && Array.isArray(value.keys)) return value.keys.map(jwkKey)
    return [jwkKey(value)]
  }

  if (trimmed.includes('-----BEGIN')) {
    const keys: VerificationKey[] = []
    for (const { label, body } of pemBlocks(trimmed)) {
      const der = base64.decode(body.replace(/\s+/g, ''))
      if (label === 'CERTIFICATE') keys.push(certificateKey(parseCertificateOrThrow(der)))
      else if (label === 'PUBLIC KEY') keys.push({ description: 'public key', key: der })
      else throw new InspectionError(`A PEM ${label.toLowerCase()} is not a key or certificate`)
    }
    if (keys.length === 0) throw new InspectionError('The PEM has no complete certificate or public key')
    return keys
  }

  const der = decodeBinaryText(trimmed)
  if (!der) throw new InspectionError('Expected a JWK, a JWK Set, or certificates as PEM, base64 or hex')
  return [certificateKey(parseCertificateOrThrow(der))]
}

/** The certificates of an `x5c` header, leaf first */
export function x5cCertificates(header: Record<string, unknown>): Certificate[] {
  if (header.x5c === undefined) return []
  if (!Array.isArray(header.x5c) || !header.x5c.every((entry) => typeof entry === 'string')) {
    throw new InspectionError('x5c must be an array of base64 encoded certificates')
  }
  return header.x5c.map((entry, index) => {
    try {
      return parseCertificate(base64.decode(entry))
    } catch (error) {
      throw new InspectionError(`x5c[${index}] cannot be parsed: ${errorMessage(error)}`)
    }
  })
}

/** Verify certificate signatures, for {@link verifyCertificateSignature} of @owf/x509 */
export const certificateVerifier =
  (crypto: Crypto): SignatureVerifier =>
  ({ data, signatureP1363, signatureAlgorithmName, publicKey }) =>
    signatureAlgorithmName
      ? verifyWith(
          crypto,
          { description: 'issuer', key: publicKey.jwk ?? publicKey.spki },
          signatureAlgorithmName,
          data,
          signatureP1363
        ).catch(() => false)
      : false

const date = (value: Date) => value.toISOString().slice(0, 10)

/** Why the certificate is not valid now, if it is not */
export function outsideValidity(certificate: Certificate, now = new Date()): string | undefined {
  if (now < certificate.notBefore) return `${certificateName(certificate)} is valid from ${date(certificate.notBefore)}`
  if (now > certificate.notAfter) return `${certificateName(certificate)} expired on ${date(certificate.notAfter)}`
  return undefined
}

/**
 * Check that a chain of certificates, leaf first, leads to one of the anchors: each
 * certificate is signed by the next, and the last is an anchor or signed by one.
 */
export async function verifyChain(
  chain: Certificate[],
  anchors: Certificate[],
  crypto: Crypto
): Promise<SignatureResult> {
  const verifier = certificateVerifier(crypto)
  for (let index = 0; index < chain.length; index++) {
    const anchor = anchors.find((candidate) => compareBytes(candidate.der, chain[index].der))
    if (anchor)
      return { status: 'valid', message: `its chain leads to the certificate you gave, ${certificateName(anchor)}` }

    const issuer = chain[index + 1]
    if (issuer) {
      if (!(await verifyCertificateSignature(chain[index], issuer, verifier))) {
        return { status: 'invalid', message: `x5c[${index}] is not signed by x5c[${index + 1}]` }
      }
      continue
    }
    for (const candidate of anchors) {
      if (await verifyCertificateSignature(chain[index], candidate, verifier)) {
        return {
          status: 'valid',
          message: `its chain leads to the certificate you gave, ${certificateName(candidate)}`,
        }
      }
    }
  }
  return { status: 'invalid', message: 'its chain does not lead to a certificate you gave' }
}

/** The key that signed the compact JWS, if one of the keys did */
export async function findSigningKey(
  jws: string,
  keys: VerificationKey[],
  crypto: Crypto
): Promise<VerificationKey | undefined> {
  const [encodedHeader, encodedPayload, encodedSignature] = jws.split('.')
  const header: unknown = JSON.parse(new TextDecoder().decode(base64url.decode(encodedHeader)))
  const alg = isRecord(header) && typeof header.alg === 'string' ? header.alg : 'none'
  const data = new TextEncoder().encode(`${encodedHeader}.${encodedPayload}`)
  const signature = base64url.decode(encodedSignature)
  for (const key of keys) {
    if (await verifyWith(crypto, key, alg, data, signature)) return key
  }
  return undefined
}

/** Where the keys to verify a JWS with come from, when not from its header */
export interface GivenKeys {
  keys: VerificationKey[]
  /** How to name where they come from, e.g. "the key you gave" */
  source: string
}

/**
 * Verify a compact JWS with the given keys, or else with the `x5c` or `jwk` of its header.
 * When the given keys are certificates and the header has an `x5c`, the chain of the `x5c`
 * has to lead to one of them.
 */
export async function verifyJwsSignature(
  jws: string,
  header: Record<string, unknown>,
  crypto: Crypto,
  given?: GivenKeys
): Promise<SignatureResult> {
  if (typeof header.alg !== 'string' || header.alg === 'none') {
    return { status: 'invalid', message: 'Not signed: alg is missing or none' }
  }
  if (!webCryptoAlgorithm(header.alg)) {
    return { status: 'unverified', message: `Not verified: the algorithm ${header.alg} is not supported` }
  }

  try {
    const chain = x5cCertificates(header)
    const validity = chain.map((certificate) => outsideValidity(certificate)).find(Boolean)
    const withValidity = (message: string) => (validity ? `${message} Note: ${validity}.` : message)

    if (given && given.keys.length > 0) {
      const signer = await findSigningKey(jws, given.keys, crypto)
      if (signer) return { status: 'valid', message: `Valid, signed with ${given.source} (${signer.description}).` }

      const anchors = given.keys.flatMap((key) => (key.certificate ? [key.certificate] : []))
      if (chain.length === 0 || anchors.length === 0) {
        return { status: 'invalid', message: `Invalid: not signed with ${given.source}.` }
      }
      if (!(await findSigningKey(jws, [certificateKey(chain[0])], crypto))) {
        return {
          status: 'invalid',
          message: `Invalid: signed neither with ${given.source} nor with the x5c certificate.`,
        }
      }
      const path = await verifyChain(chain, anchors, crypto)
      const leaf = certificateName(chain[0])
      return path.status === 'valid'
        ? {
            status: 'valid',
            message: withValidity(`Valid, signed with the x5c certificate ${leaf}, and ${path.message}.`),
          }
        : { status: 'invalid', message: `Invalid: signed with the x5c certificate ${leaf}, but ${path.message}.` }
    }

    if (chain.length > 0) {
      const leaf = certificateName(chain[0])
      return (await findSigningKey(jws, [certificateKey(chain[0])], crypto))
        ? {
            status: 'valid',
            message: withValidity(
              `Valid, signed with the key of the x5c certificate ${leaf}. This proves integrity only: give the certificate of a trust anchor to check the chain.`
            ),
          }
        : { status: 'invalid', message: `Invalid: not signed with the key of the x5c certificate ${leaf}.` }
    }

    if (isRecord(header.jwk)) {
      return (await findSigningKey(jws, [jwkKey(header.jwk)], crypto))
        ? { status: 'valid', message: 'Valid, signed with the jwk of the header. This proves integrity only.' }
        : { status: 'invalid', message: 'Invalid: not signed with the jwk of the header.' }
    }

    const kid = typeof header.kid === 'string' ? ` with the kid ${header.kid}` : ''
    return {
      status: 'unverified',
      message: `Not verified: the header has no x5c, so give the key${kid} of the signer.`,
    }
  } catch (error) {
    return { status: 'invalid', message: `Invalid: ${errorMessage(error)}` }
  }
}

/** Read the keys the user gave, as {@link GivenKeys}, or the reason they cannot be read */
export function givenKeys(text: string | undefined, source = 'the key you gave'): GivenKeys | string | undefined {
  if (!text?.trim()) return undefined
  try {
    return { keys: parseKeys(text), source }
  } catch (error) {
    return `The key you gave cannot be read: ${errorMessage(error)}`
  }
}

/** The signature check of a compact JWS, with the keys the user gave, if any */
export function jwsSignatureCheck(
  jws: string,
  header: Record<string, unknown>,
  keyText?: string,
  label = 'Signature'
): SignatureCheck {
  return {
    label,
    verify: async (crypto) => {
      const given = givenKeys(keyText)
      if (typeof given === 'string') return { status: 'unverified', message: given }
      return verifyJwsSignature(jws, header, crypto, given)
    },
  }
}
