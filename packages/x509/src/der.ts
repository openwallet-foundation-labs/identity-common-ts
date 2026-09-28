import { base64url, concatBytes, hexEncode, type JsonWebKey } from '@owf/identity-common'
import { AsnConvert } from '@peculiar/asn1-schema'
import { AlgorithmIdentifier, SubjectPublicKeyInfo } from '@peculiar/asn1-x509'
import * as asn1js from 'asn1js'
import { KEY_ALGORITHMS } from './constants'
import { toArrayBuffer } from './encoding'
import type { ParsedPublicKey } from './types'
import { X509Exception } from './x509-exception'

const CURVES = {
  'P-256': { oid: KEY_ALGORITHMS['P-256'], size: 32 },
  'P-384': { oid: KEY_ALGORITHMS['P-384'], size: 48 },
  'P-521': { oid: KEY_ALGORITHMS['P-521'], size: 66 },
} as const

type CurveName = keyof typeof CURVES

/** Byte length of a coordinate (and of r and s in an ECDSA signature) for a named curve OID */
export function curveCoordinateLength(namedCurve: string | undefined): number | undefined {
  return Object.values(CURVES).find((c) => c.oid === namedCurve)?.size
}

/** Parse a single DER value, rejecting trailing or malformed data. */
export function parseDer(bytes: Uint8Array | ArrayBuffer): asn1js.AsnType {
  const buffer = bytes instanceof Uint8Array ? toArrayBuffer(bytes) : bytes
  const result = asn1js.fromBER(buffer)
  if (result.offset === -1 || result.offset !== buffer.byteLength) {
    throw new X509Exception('Invalid DER encoding')
  }
  return result.result
}

/** Decode an ASN.1 string type (or unwrap an explicit tag around one) to a JS string. */
export function asn1ToString(node: asn1js.AsnType): string | undefined {
  if (node instanceof asn1js.BaseStringBlock) return node.getValue()
  if (node instanceof asn1js.Constructed && node.valueBlock.value.length === 1) {
    return asn1ToString(node.valueBlock.value[0])
  }
  return undefined
}

/** Strip leading zeros from an unsigned big endian integer. */
function stripLeadingZeros(bytes: Uint8Array): Uint8Array {
  let i = 0
  while (i < bytes.length - 1 && bytes[i] === 0) i++
  return bytes.subarray(i)
}

/**
 * Encode unsigned big endian bytes as the content of a DER INTEGER, adding a leading
 * zero when the high bit is set so the value stays positive.
 */
export function toPositiveIntegerBytes(bytes: Uint8Array): Uint8Array {
  const stripped = stripLeadingZeros(bytes)
  return stripped[0] & 0x80 ? concatBytes(new Uint8Array([0]), stripped) : stripped
}

function integer(bytes: Uint8Array): asn1js.Integer {
  return new asn1js.Integer({ valueHex: toArrayBuffer(toPositiveIntegerBytes(bytes)) })
}

function leftPad(bytes: Uint8Array, length: number): Uint8Array {
  const stripped = stripLeadingZeros(bytes)
  if (stripped.length > length) {
    throw new X509Exception('Integer does not fit the expected length')
  }
  const out = new Uint8Array(length)
  out.set(stripped, length - stripped.length)
  return out
}

/** Convert an IEEE P1363 (r || s) ECDSA signature to DER. */
export function ecdsaP1363ToDer(signature: Uint8Array, coordinateLength: number): Uint8Array {
  if (signature.length !== coordinateLength * 2) {
    throw new X509Exception(
      `Expected a ${coordinateLength * 2} byte IEEE P1363 ECDSA signature, got ${signature.length} bytes`
    )
  }
  const seq = new asn1js.Sequence({
    value: [integer(signature.subarray(0, coordinateLength)), integer(signature.subarray(coordinateLength))],
  })
  return new Uint8Array(seq.toBER())
}

/** Convert a DER ECDSA signature to IEEE P1363 (r || s). */
export function ecdsaDerToP1363(signature: Uint8Array, coordinateLength: number): Uint8Array {
  const seq = parseDer(signature)
  if (!(seq instanceof asn1js.Sequence) || seq.valueBlock.value.length !== 2) {
    throw new X509Exception('Invalid DER ECDSA signature')
  }
  const [r, s] = seq.valueBlock.value
  if (!(r instanceof asn1js.Integer) || !(s instanceof asn1js.Integer)) {
    throw new X509Exception('Invalid DER ECDSA signature')
  }
  return concatBytes(
    leftPad(new Uint8Array(r.valueBlock.valueHexView), coordinateLength),
    leftPad(new Uint8Array(s.valueBlock.valueHexView), coordinateLength)
  )
}

/**
 * Convert a public JWK to a DER SubjectPublicKeyInfo. Refuses private keys: only the
 * public part of the wallet-relying party key is needed to issue its certificate.
 */
export function publicJwkToSpki(jwk: JsonWebKey): Uint8Array {
  if (jwk.d !== undefined || jwk.p !== undefined || jwk.q !== undefined) {
    throw new X509Exception('The subject public key must not contain private key material')
  }
  if (jwk.kty === 'EC') {
    const curve = CURVES[jwk.crv as CurveName]
    if (!curve || !jwk.x || !jwk.y) {
      throw new X509Exception(`Unsupported EC public key (crv: ${jwk.crv})`)
    }
    const point = concatBytes(
      new Uint8Array([4]),
      leftPad(base64url.decode(jwk.x), curve.size),
      leftPad(base64url.decode(jwk.y), curve.size)
    )
    const spki = new SubjectPublicKeyInfo({
      algorithm: new AlgorithmIdentifier({
        algorithm: KEY_ALGORITHMS.ecPublicKey,
        parameters: new asn1js.ObjectIdentifier({ value: curve.oid }).toBER(),
      }),
      subjectPublicKey: toArrayBuffer(point),
    })
    return new Uint8Array(AsnConvert.serialize(spki))
  }
  if (jwk.kty === 'RSA') {
    if (!jwk.n || !jwk.e) throw new X509Exception('RSA public key requires n and e')
    const rsaPublicKey = new asn1js.Sequence({
      value: [integer(base64url.decode(jwk.n)), integer(base64url.decode(jwk.e))],
    })
    const spki = new SubjectPublicKeyInfo({
      algorithm: new AlgorithmIdentifier({ algorithm: KEY_ALGORITHMS.rsaEncryption, parameters: null }),
      subjectPublicKey: rsaPublicKey.toBER(),
    })
    return new Uint8Array(AsnConvert.serialize(spki))
  }
  throw new X509Exception(`Unsupported key type: ${jwk.kty}`)
}

/** Describe a SubjectPublicKeyInfo, including a JWK for EC and RSA keys. */
export function describePublicKey(spki: SubjectPublicKeyInfo): ParsedPublicKey {
  const der = new Uint8Array(AsnConvert.serialize(spki))
  const algorithm = spki.algorithm.algorithm
  const key = new Uint8Array(spki.subjectPublicKey)

  if (algorithm === KEY_ALGORITHMS.ecPublicKey && spki.algorithm.parameters) {
    const namedCurveNode = parseDer(spki.algorithm.parameters)
    const namedCurve =
      namedCurveNode instanceof asn1js.ObjectIdentifier ? namedCurveNode.valueBlock.toString() : undefined
    const entry = Object.entries(CURVES).find(([, c]) => c.oid === namedCurve)
    let jwk: JsonWebKey | undefined
    if (entry && key[0] === 4 && key.length === 1 + entry[1].size * 2) {
      const size = entry[1].size
      jwk = {
        kty: 'EC',
        crv: entry[0],
        x: base64url.encode(key.subarray(1, 1 + size)),
        y: base64url.encode(key.subarray(1 + size)),
      }
    }
    return { algorithm, namedCurve, spki: der, jwk }
  }

  if (algorithm === KEY_ALGORITHMS.rsaEncryption) {
    let jwk: JsonWebKey | undefined
    try {
      const seq = parseDer(key)
      if (seq instanceof asn1js.Sequence) {
        const [n, e] = seq.valueBlock.value
        if (n instanceof asn1js.Integer && e instanceof asn1js.Integer) {
          jwk = {
            kty: 'RSA',
            n: base64url.encode(stripLeadingZeros(new Uint8Array(n.valueBlock.valueHexView))),
            e: base64url.encode(stripLeadingZeros(new Uint8Array(e.valueBlock.valueHexView))),
          }
        }
      }
    } catch {
      // Leave jwk undefined for malformed RSA keys
    }
    return { algorithm, spki: der, jwk }
  }

  return { algorithm, spki: der }
}

export function toHex(bytes: ArrayBuffer | Uint8Array): string {
  return hexEncode(bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes))
}

function derLength(length: number): Uint8Array {
  if (length < 0x80) return new Uint8Array([length])
  const bytes: number[] = []
  for (let l = length; l > 0; l >>= 8) bytes.unshift(l & 0xff)
  return new Uint8Array([0x80 | bytes.length, ...bytes])
}

/** Encode a single DER TLV. */
export function derTlv(tag: number, content: Uint8Array): Uint8Array {
  return concatBytes(new Uint8Array([tag]), derLength(content.length), content)
}

/** Interpret big endian two's complement INTEGER content as a bigint (non-negative values only). */
export function integerBytesToBigInt(bytes: Uint8Array): bigint {
  return bytes.length === 0 ? BigInt(0) : BigInt(`0x${hexEncode(bytes)}`)
}
