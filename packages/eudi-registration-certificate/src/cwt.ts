/**
 * Registration certificates in CWT format (GEN-5.2.1-01, GEN-5.2.1-05 and clause 5.2.3).
 *
 * ETSI TS 119 475 v1.2.1 lists the payload fields once for both formats and assigns them no CBOR labels. The claims set
 * is the payload of the JWT as a CBOR map, with the fields that have a registered CWT claim under its key and the other
 * fields under their JSON name.
 *
 * @see https://www.etsi.org/deliver/etsi_ts/119400_119499/119475/01.02.01_60/ts_119475v010201p.pdf
 */

import {
  type AnyCwt,
  Cwt,
  CwtPayload,
  type CwtStaticThis,
  type CwtStructures,
  RegisteredCwtClaimKey,
  RegisteredCwtHeaderClaimKey,
  SignatureAlgorithm,
  TypedMap,
} from '@owf/cose'
import { pemToDer } from '@owf/crypto'
import {
  base64,
  bytesToString,
  concatBytes,
  prefixIssuePaths,
  stringToBytes,
  toValidationResult,
} from '@owf/identity-common'
import {
  REGISTRATION_CERTIFICATE_DIALECTS,
  type RegistrationCertificateDialect,
  toRegistrationCertificateDialect,
} from './dialect'
import { RegistrationCertificateValidationError } from './registration-certificate-error'
import type {
  RegistrationCertificateCwtHeader,
  RegistrationCertificatePayload,
  SignCwtOptions,
  SignedRegistrationCertificateCwt,
  VerifyCoseCallback,
} from './types'
import {
  assertValidRegistrationCertificatePayload,
  asValidationError,
  parseRegistrationCertificatePayload,
  validateRegistrationCertificateCwtHeader,
  validateRegistrationCertificatePayload,
  validationError,
} from './validator'

/**
 * The payload fields with a registered CWT claim (IANA CWT Claims registry), and its key. ETSI TS 119 475 does not say
 * whether a CWT uses these or the JSON names, so both are read.
 */
const CWT_CLAIM_KEYS = new Map<string, number>([
  ['sub', RegisteredCwtClaimKey.Subject],
  ['exp', RegisteredCwtClaimKey.ExpirationTime],
  ['iat', RegisteredCwtClaimKey.IssuedAt],
  // A byte string in a CWT (RFC 8392 section 3.1.7), so it holds the UTF-8 bytes of `jti`
  ['jti', RegisteredCwtClaimKey.CwtId],
  // Token Status List section 6.3
  ['status', 65535],
])
const CWT_CLAIM_NAMES = new Map<unknown, string>(Array.from(CWT_CLAIM_KEYS, ([name, key]) => [key, name]))

/**
 * The claims set of a CWT registration certificate, as a CBOR structure that can be extended or modified before it is
 * signed. Decoding only checks the CBOR types of the registered claims: the registration certificate is validated as its
 * JSON form, {@link registrationCertificate}.
 */
export class RegistrationCertificateCwtPayload extends CwtPayload {
  /** The claims set of a registration certificate payload, in the dialect given */
  public static fromRegistrationCertificate(
    payload: RegistrationCertificatePayload,
    dialect: RegistrationCertificateDialect = REGISTRATION_CERTIFICATE_DIALECTS.CURRENT
  ): RegistrationCertificateCwtPayload {
    // Through JSON, so that members left `undefined` are dropped as they are from a JWT
    const json: Record<string, unknown> = JSON.parse(JSON.stringify(toRegistrationCertificateDialect(payload, dialect)))
    const claims = new Map(
      Object.entries(json).map(([name, value]) => [
        CWT_CLAIM_KEYS.get(name) ?? name,
        name === 'jti' ? stringToBytes(value as string) : value,
      ])
    )

    // biome-ignore lint/complexity/noThisInStatic: this.fromDecodedStructure is intentional for subclass support
    return this.fromDecodedStructure(TypedMap.fromMap(claims))
  }

  /**
   * The payload as the JSON object of a JWT registration certificate, with the registered claims under their name
   * whichever key they had. Not validated.
   *
   * @throws RegistrationCertificateValidationError if a field is under both its name and its CWT claim key
   */
  public get registrationCertificate(): Record<string, unknown> {
    const entries: Array<[string, unknown]> = []
    for (const [key, value] of this.claims.entries()) {
      // Other integer keys, such as `iss`, are not fields of a registration certificate
      const name = typeof key === 'string' ? key : CWT_CLAIM_NAMES.get(key)
      if (name === undefined) continue

      if (entries.some(([existing]) => existing === name)) {
        throw validationError('Invalid registration certificate payload', {
          code: 'invalid_value',
          path: [name],
          message: `${name} is under both its name and its CWT claim key`,
        })
      }
      entries.push([name, key === RegisteredCwtClaimKey.CwtId ? cwtIdToJti(value) : toJson(value)])
    }
    return Object.fromEntries(entries)
  }
}

/** A registration certificate in CWT format: a COSE_Sign1 with a {@link RegistrationCertificateCwtPayload} */
export class RegistrationCertificateCwt extends Cwt<RegistrationCertificateCwtPayload> {
  /**
   * Decode a tagged (tag 18) or untagged COSE_Sign1, as RFC 8392 section 6 leaves the tag to the application and some
   * issuers leave it out
   */
  public static override fromToken<T extends AnyCwt>(this: CwtStaticThis<T>, token: Uint8Array): T {
    // An untagged COSE_Sign1 is an array of four (0x84), which tag 18 (0xd2) in front of it turns into a tagged one
    const tagged = token[0] === 0x84 ? concatBytes(new Uint8Array([0xd2]), token) : token
    // biome-ignore lint/complexity/noThisInStatic: dispatching to the subclass is intentional
    return super.fromToken(tagged, { payload: RegistrationCertificateCwtPayload } as unknown as CwtStructures<T>) as T
  }
}

/**
 * Sign a registration certificate payload into a CWT: a tagged COSE_Sign1 whose protected header holds `alg`, `typ` (RFC
 * 9596) and the `x5chain` (RFC 9360) of `certificates`.
 *
 * @throws RegistrationCertificateValidationError if the payload is not valid, or `certificates` or the algorithm is missing
 */
export async function signRegistrationCertificateCwt(
  options: SignCwtOptions
): Promise<SignedRegistrationCertificateCwt> {
  const { accessCertificateSub, certificates, signingKey, algorithm = signingKey.algorithm, signCoseCallback } = options
  const payload =
    options.payload instanceof RegistrationCertificateCwtPayload
      ? options.payload
      : RegistrationCertificateCwtPayload.fromRegistrationCertificate(options.payload, options.dialect)

  const json = payload.registrationCertificate
  assertValidRegistrationCertificatePayload(json, accessCertificateSub)

  if (certificates.length === 0) {
    throw validationError('Unable to sign the registration certificate', {
      code: 'missing_value',
      path: ['certificates'],
      message: 'At least one certificate is required for the x5chain header',
      context: { expected: 'certificate' },
    })
  }
  if (algorithm === undefined) {
    throw validationError('Unable to sign the registration certificate', {
      code: 'missing_value',
      path: ['algorithm'],
      message: 'No algorithm given, and the signing key has none',
      context: { expected: 'algorithm' },
    })
  }

  const x5chain = certificates.map((certificate) => base64.decode(pemToDer(certificate)))
  const cwt = new RegistrationCertificateCwt({
    payload,
    protectedHeaders: new Map<number, unknown>([
      [RegisteredCwtHeaderClaimKey.Algorithm, algorithm],
      [RegisteredCwtHeaderClaimKey.Typ, 'rc-wrp+cwt'],
      // RFC 9360 section 2: one certificate is a byte string, a chain an array of at least two
      [RegisteredCwtHeaderClaimKey.X5Chain, x5chain.length === 1 ? x5chain[0] : x5chain],
    ]),
  })

  return {
    // Sign1 rejects an algorithm that is not a signature algorithm
    cwt: await cwt.signAndEncode(
      { signingKey, algorithm: algorithm as SignatureAlgorithm },
      { sign: signCoseCallback }
    ),
    header: { typ: 'rc-wrp+cwt', alg: algorithm, x5chain } as RegistrationCertificateCwtHeader,
    payload: parseRegistrationCertificatePayload(json, accessCertificateSub),
  }
}

/**
 * Decode a CWT registration certificate (without cryptographic verification) and validate its header and payload.
 *
 * The COSE_Sign1 may be tagged (tag 18) or untagged. The header is read from the protected bucket only: `typ` must not be
 * unprotected (RFC 9596 section 2), and the signer's chain is part of the signed data of an advanced electronic signature
 * (GEN-5.2.1-05).
 *
 * @param cwt - The encoded COSE_Sign1
 * @returns Decoded registration certificate with header and payload
 * @throws RegistrationCertificateValidationError with the issues, whose paths start with `header` or `payload`
 */
export function decodeRegistrationCertificateCwt(
  cwt: Uint8Array,
  accessCertificateSub: string
): SignedRegistrationCertificateCwt {
  const { registrationCertificateCwt: _, ...decoded } = parseRegistrationCertificateCwt(cwt, accessCertificateSub)
  return decoded
}

/** {@link decodeRegistrationCertificateCwt}, with the decoded CWT to verify the signature of */
export function parseRegistrationCertificateCwt(
  cwt: Uint8Array,
  accessCertificateSub: string
): SignedRegistrationCertificateCwt & { registrationCertificateCwt: RegistrationCertificateCwt } {
  let token: RegistrationCertificateCwt
  try {
    token = RegistrationCertificateCwt.fromToken(cwt)
  } catch (error) {
    throw asValidationError(error, 'Invalid registration certificate', {
      code: 'invalid_format',
      context: { format: 'CWT' },
    })
  }

  if (token.signature === undefined) {
    throw validationError('Invalid registration certificate', {
      code: 'invalid_format',
      message: 'A registration certificate is signed as a COSE_Sign1 (GEN-5.2.1-05)',
      context: { format: 'COSE_Sign1' },
    })
  }

  const headers = token.protectedHeaders.headers
  // RFC 9052 section 3.1: a recipient must understand every parameter `crit` lists, and none is understood here
  const crit = headers.get(RegisteredCwtHeaderClaimKey.Critical)
  if (crit !== undefined) {
    throw validationError('Invalid registration certificate', {
      code: 'unsupported_crit',
      path: ['header', 'crit'],
      message: 'The crit header is not supported',
      context: { parameter: String(crit[0]), understood: [] },
    })
  }

  const x5chain = headers.get(RegisteredCwtHeaderClaimKey.X5Chain)
  const header = {
    typ: headers.get(RegisteredCwtHeaderClaimKey.Typ),
    alg: headers.get(RegisteredCwtHeaderClaimKey.Algorithm),
    x5chain: x5chain instanceof Uint8Array ? [x5chain] : x5chain,
  }

  let json: Record<string, unknown>
  try {
    json = token.payload.registrationCertificate
  } catch (error) {
    throw asValidationError(error, 'Invalid registration certificate', { code: 'invalid_value', path: ['payload'] })
  }

  const result = toValidationResult([
    ...prefixIssuePaths('header', validateRegistrationCertificateCwtHeader(header).issues),
    ...prefixIssuePaths('payload', validateRegistrationCertificatePayload(json, accessCertificateSub).issues),
  ])
  if (!result.valid) throw new RegistrationCertificateValidationError('Invalid registration certificate', result.issues)

  return {
    cwt,
    header: header as RegistrationCertificateCwtHeader,
    payload: parseRegistrationCertificatePayload(json, accessCertificateSub),
    registrationCertificateCwt: token,
  }
}

/**
 * Verify the signature of a CWT through `verifyCose`, with the `x5chain` of its protected header
 *
 * @throws RegistrationCertificateValidationError if it has no protected `x5chain` or signature algorithm, or the signature
 *   does not verify
 */
export async function verifyCwtSignature(cwt: AnyCwt, verifyCose: VerifyCoseCallback): Promise<void> {
  const headers = cwt.protectedHeaders.headers
  const x5chain = headers.get(RegisteredCwtHeaderClaimKey.X5Chain)
  const algorithm = headers.get(RegisteredCwtHeaderClaimKey.Algorithm)

  if (!(x5chain instanceof Uint8Array) && !Array.isArray(x5chain)) {
    throw validationError('Invalid signature', {
      code: 'missing_value',
      path: ['header', 'x5chain'],
      message: 'The COSE_Sign1 has no x5chain in its protected header',
      context: { expected: 'x5chain' },
    })
  }
  if (typeof algorithm !== 'number' || SignatureAlgorithm[algorithm] === undefined || cwt.signature === undefined) {
    throw validationError('Invalid signature', {
      code: 'invalid_value',
      path: ['header', 'alg'],
      message: 'The CWT is not a COSE_Sign1 with a signature algorithm in its protected header',
    })
  }

  const verified = await verifyCose({
    x5chain: x5chain instanceof Uint8Array ? [x5chain] : x5chain,
    algorithm,
    toBeVerified: cwt.asSign1.toBeSigned(),
    signature: cwt.signature,
  })
  if (!verified) {
    throw validationError('Invalid signature', {
      code: 'invalid_signature',
      message: 'The signature of the COSE_Sign1 is not valid',
    })
  }
}

/** A `cti` that is not UTF-8 is left for the payload schema to reject as `jti` */
const cwtIdToJti = (cti: unknown) => {
  try {
    return bytesToString(cti as Uint8Array, { fatal: true })
  } catch {
    return cti
  }
}

const toJson = (value: unknown): unknown =>
  value instanceof Map
    ? Object.fromEntries(Array.from(value, ([key, entry]) => [String(key), toJson(entry)]))
    : Array.isArray(value)
      ? value.map(toJson)
      : value
