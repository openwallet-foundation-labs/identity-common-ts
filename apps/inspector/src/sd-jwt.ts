import { hasher } from '@owf/crypto'
import { base64url, decodeJwt, type Finding, type FindingSeverity } from '@owf/identity-common'
import { Disclosure, getSDAlgAndPayload, unpackSync } from '@sd-jwt/core'
import { type DocumentInput, errorMessage, isRecord, JWS, toText } from './input'
import { type Inspection, InspectionError, type SignatureCheck } from './inspection'
import { jwsSignatureCheck, parseKeys, verifyJwsSignature } from './signature'

export interface SdJwtOptions {
  /** The key or certificates of the issuer */
  key?: string
  /** The nonce the verifier sent, which the Key Binding JWT has to hold */
  nonce?: string
  /** The audience the Key Binding JWT has to be for, the client_id of the verifier */
  aud?: string
}

/** Codes of the findings of an SD-JWT inspection */
export const SD_JWT_CODES = {
  /** The SD-JWT has no `~` separator */
  MISSING_SEPARATOR: 'missing_separator',
  /** `alg` is missing or `none` */
  INVALID_ALG: 'invalid_alg',
  /** `typ` is not `dc+sd-jwt` for an SD-JWT VC */
  INVALID_TYP: 'invalid_typ',
  /** `_sd_alg` is not an allowed hash algorithm */
  INVALID_SD_ALG: 'invalid_sd_alg',
  /** A disclosure is not a base64url encoded JSON array of salt, name and value */
  INVALID_DISCLOSURE: 'invalid_disclosure',
  /** The same disclosure is presented twice */
  DUPLICATE_DISCLOSURE: 'duplicate_disclosure',
  /** No digest in the payload or another disclosure references the disclosure (RFC 9901 Section 7.1) */
  UNREFERENCED_DISCLOSURE: 'unreferenced_disclosure',
  /** The claims cannot be resolved from the payload and the disclosures */
  INVALID_PAYLOAD: 'invalid_payload',
  /** `vct` is missing for an SD-JWT VC */
  MISSING_VCT: 'missing_vct',
  /** A claim that an SD-JWT VC must not disclose selectively is disclosed */
  PROTECTED_CLAIM_DISCLOSED: 'protected_claim_disclosed',
  /** `iat`, `nbf` or `exp` is not a number of seconds */
  INVALID_TIME_CLAIM: 'invalid_time_claim',
  /** `nbf` or `iat` is in the future */
  NOT_YET_VALID: 'not_yet_valid',
  /** `exp` is in the past */
  EXPIRED: 'expired',
  /** `status` is not a status list reference with `idx` and `uri` */
  INVALID_STATUS: 'invalid_status',
  /** There is a Key Binding JWT, but no `cnf` to bind it to */
  MISSING_CNF: 'missing_cnf',
  /** The `typ` of the Key Binding JWT is not `kb+jwt` (RFC 9901 Section 4.3) */
  INVALID_KB_TYP: 'invalid_kb_typ',
  /** A required claim of the Key Binding JWT is missing (RFC 9901 Section 4.3) */
  MISSING_KB_CLAIM: 'missing_kb_claim',
  /** `sd_hash` of the Key Binding JWT is not the hash of the presented SD-JWT (RFC 9901 Section 4.3) */
  SD_HASH_MISMATCH: 'sd_hash_mismatch',
  /** `nonce` of the Key Binding JWT is not the one the verifier sent */
  KB_NONCE_MISMATCH: 'kb_nonce_mismatch',
  /** `aud` of the Key Binding JWT is not the verifier */
  KB_AUD_MISMATCH: 'kb_aud_mismatch',
} as const

type SdJwtCode = (typeof SD_JWT_CODES)[keyof typeof SD_JWT_CODES]

const C = SD_JWT_CODES
// Claims an SD-JWT VC must not disclose selectively, as `@sd-jwt/sd-jwt-vc` enforces when issuing
const PROTECTED_CLAIMS = ['iss', 'nbf', 'exp', 'cnf', 'vct', 'status']
const SKEW_SECONDS = 30

const hasherSync = (data: string, alg: string) => hasher(data, alg)

/** Every digest referenced by `_sd` arrays and `{"...": digest}` array elements */
function referencedDigests(value: unknown, digests = new Set<string>()): Set<string> {
  if (Array.isArray(value)) {
    for (const element of value) {
      if (isRecord(element) && Object.keys(element).length === 1 && typeof element['...'] === 'string') {
        digests.add(element['...'])
      } else {
        referencedDigests(element, digests)
      }
    }
  } else if (isRecord(value)) {
    for (const [key, member] of Object.entries(value)) {
      if (key === '_sd' && Array.isArray(member)) {
        for (const digest of member) if (typeof digest === 'string') digests.add(digest)
      } else {
        referencedDigests(member, digests)
      }
    }
  }
  return digests
}

/**
 * Decode an SD-JWT, or an SD-JWT VC, check its disclosures, its claims and its Key Binding
 * JWT, and verify its signatures.
 */
export function inspectSdJwt(input: DocumentInput, options: SdJwtOptions = {}): Inspection {
  const text = toText(input).replace(/\s+/g, '')
  if (!text) throw new InspectionError('There is nothing to inspect')
  if (!JWS.test(text.split('~')[0])) throw new InspectionError('An SD-JWT starts with a JWT, and this does not')
  const findings: Finding<SdJwtCode>[] = []
  const add = (
    severity: FindingSeverity,
    code: SdJwtCode,
    path: (string | number)[],
    message: string,
    requirement?: string
  ) => findings.push({ severity, code, path, message, ...(requirement ? { requirement } : {}) })

  // <issuer-signed JWT>~<disclosure>~…~<disclosure>~<optional key binding JWT>
  const parts = text.split('~')
  const keyBindingJwt = parts.length > 1 && parts[parts.length - 1] ? parts[parts.length - 1] : undefined
  const encodedDisclosures = parts.slice(1, -1)

  let header: Record<string, unknown>
  let payload: Record<string, unknown>
  try {
    ;({ header, payload } = decodeJwt<Record<string, unknown>, Record<string, unknown>>(parts[0]))
  } catch (error) {
    throw new InspectionError(`The issuer-signed JWT of the SD-JWT cannot be decoded: ${errorMessage(error)}`)
  }
  if (parts.length === 1) {
    add('error', C.MISSING_SEPARATOR, [], 'An SD-JWT ends with ~ after the issuer-signed JWT and each disclosure')
  }

  const isVc = 'vct' in payload || ['dc+sd-jwt', 'vc+sd-jwt'].includes(String(header.typ))

  // Header
  if (typeof header.alg !== 'string' || header.alg === 'none') {
    add('error', C.INVALID_ALG, ['header', 'alg'], 'alg must name a signature algorithm, and must not be none')
  }
  if (isVc && header.typ === 'vc+sd-jwt') {
    add('warning', C.INVALID_TYP, ['header', 'typ'], 'typ vc+sd-jwt is the media type of earlier drafts, now dc+sd-jwt')
  } else if (isVc && header.typ !== 'dc+sd-jwt') {
    add('error', C.INVALID_TYP, ['header', 'typ'], `typ is ${String(header.typ ?? '(none)')}, it must be dc+sd-jwt`)
  }

  // Hash algorithm of the disclosures
  let sdAlg = 'sha-256'
  try {
    sdAlg = getSDAlgAndPayload(payload)._sd_alg
  } catch (error) {
    add('error', C.INVALID_SD_ALG, ['payload', '_sd_alg'], errorMessage(error))
  }

  // Disclosures
  const disclosures: (Disclosure | undefined)[] = encodedDisclosures.map((encoded, index) => {
    try {
      return Disclosure.fromEncodeSync(encoded, { alg: sdAlg, hasher: hasherSync })
    } catch (error) {
      add('error', C.INVALID_DISCLOSURE, ['disclosures', index], errorMessage(error))
      return undefined
    }
  })
  const decoded = disclosures.filter((disclosure): disclosure is Disclosure => disclosure !== undefined)
  const referenced = referencedDigests([payload, ...decoded.map((disclosure) => disclosure.value)])
  const seen = new Set<string>()
  disclosures.forEach((disclosure, index) => {
    if (!disclosure?._digest) return
    if (seen.has(disclosure._digest)) {
      add('error', C.DUPLICATE_DISCLOSURE, ['disclosures', index], 'This disclosure is presented twice')
    } else if (!referenced.has(disclosure._digest)) {
      add(
        'error',
        C.UNREFERENCED_DISCLOSURE,
        ['disclosures', index],
        'No digest in the payload or in another disclosure references this disclosure',
        'RFC 9901 Section 7.1'
      )
    }
    seen.add(disclosure._digest)
  })

  // Claims, with the claim each disclosure discloses
  let claims: Record<string, unknown> | undefined
  const claimOfDigest = new Map<string, string>()
  if (findings.every((finding) => finding.severity !== 'error' || finding.path[0] === 'header')) {
    try {
      const { unpackedObj, disclosureKeymap } = unpackSync(payload, decoded, hasherSync)
      claims = unpackedObj as Record<string, unknown>
      for (const [claim, digest] of Object.entries(disclosureKeymap)) claimOfDigest.set(digest, claim)
    } catch (error) {
      add('error', C.INVALID_PAYLOAD, ['payload'], `The claims cannot be resolved: ${errorMessage(error)}`)
    }
  }

  // SD-JWT VC claims, on the resolved claims
  if (isVc && claims) {
    if (typeof claims.vct !== 'string') add('error', C.MISSING_VCT, ['claims', 'vct'], 'vct must be a string')
    for (const claim of PROTECTED_CLAIMS) {
      const digest = [...claimOfDigest].find(([, name]) => name === claim)?.[0]
      if (digest) {
        add('error', C.PROTECTED_CLAIM_DISCLOSED, ['claims', claim], `${claim} must not be disclosed selectively`)
      }
    }
    const status = claims.status
    if (status !== undefined) {
      const reference = isRecord(status) ? status.status_list : undefined
      if (
        !isRecord(reference) ||
        !Number.isInteger(reference.idx) ||
        (reference.idx as number) < 0 ||
        typeof reference.uri !== 'string'
      ) {
        add('error', C.INVALID_STATUS, ['claims', 'status'], 'status must hold a status_list with an idx and a uri')
      }
    }
  }

  // Validity window
  const timeSource = claims ?? payload
  const timePath = claims ? 'claims' : 'payload'
  const now = Date.now()
  for (const claim of ['iat', 'nbf', 'exp'] as const) {
    const value = timeSource[claim]
    if (value === undefined) continue
    if (typeof value !== 'number' || !Number.isFinite(value)) {
      add('error', C.INVALID_TIME_CLAIM, [timePath, claim], `${claim} must be a number of seconds since the epoch`)
      continue
    }
    const date = new Date(value * 1000)
    if (claim !== 'exp' && date.getTime() - SKEW_SECONDS * 1000 > now) {
      add('error', C.NOT_YET_VALID, [timePath, claim], `${claim} ${date.toISOString()} is in the future`)
    }
    if (claim === 'exp' && date.getTime() + SKEW_SECONDS * 1000 <= now) {
      add('error', C.EXPIRED, [timePath, claim], `The SD-JWT expired at ${date.toISOString()}`)
    }
  }

  // Key Binding JWT
  let keyBinding: { header: Record<string, unknown>; payload: Record<string, unknown> } | undefined
  if (keyBindingJwt) {
    try {
      keyBinding = decodeJwt<Record<string, unknown>, Record<string, unknown>>(keyBindingJwt)
    } catch (error) {
      throw new InspectionError(`The Key Binding JWT cannot be decoded: ${errorMessage(error)}`)
    }
    if (!isRecord(timeSource.cnf)) {
      add('error', C.MISSING_CNF, [timePath], 'There is a Key Binding JWT, but no cnf claim with the key to verify it')
    }
    if (keyBinding.header.typ !== 'kb+jwt') {
      add(
        'error',
        C.INVALID_KB_TYP,
        ['key_binding', 'header', 'typ'],
        `typ is ${String(keyBinding.header.typ ?? '(none)')}, it must be kb+jwt`,
        'RFC 9901 Section 4.3'
      )
    }
    for (const claim of ['iat', 'aud', 'nonce', 'sd_hash']) {
      if (keyBinding.payload[claim] === undefined) {
        add(
          'error',
          C.MISSING_KB_CLAIM,
          ['key_binding', 'payload', claim],
          `${claim} is missing`,
          'RFC 9901 Section 4.3'
        )
      }
    }
    const nonce = options.nonce?.trim()
    if (nonce && keyBinding.payload.nonce !== undefined && keyBinding.payload.nonce !== nonce) {
      add(
        'error',
        C.KB_NONCE_MISMATCH,
        ['key_binding', 'payload', 'nonce'],
        `nonce is not the one the verifier sent, ${nonce}`,
        'RFC 9901 Section 7.3'
      )
    }
    const aud = options.aud?.trim()
    const audiences = Array.isArray(keyBinding.payload.aud) ? keyBinding.payload.aud : [keyBinding.payload.aud]
    if (aud && keyBinding.payload.aud !== undefined && !audiences.includes(aud)) {
      add(
        'error',
        C.KB_AUD_MISMATCH,
        ['key_binding', 'payload', 'aud'],
        `aud is not the verifier, ${aud}`,
        'RFC 9901 Section 7.3'
      )
    }
    const sdHash = base64url.encode(hasher(text.slice(0, text.lastIndexOf('~') + 1), sdAlg))
    if (keyBinding.payload.sd_hash !== undefined && keyBinding.payload.sd_hash !== sdHash) {
      add(
        'error',
        C.SD_HASH_MISMATCH,
        ['key_binding', 'payload', 'sd_hash'],
        `sd_hash is not the ${sdAlg} hash of the presented SD-JWT, which is ${sdHash}`,
        'RFC 9901 Section 4.3'
      )
    }
  }

  const value: Record<string, unknown> = {
    header,
    payload,
    disclosures: disclosures.map((disclosure, index) =>
      disclosure
        ? {
            digest: disclosure._digest,
            ...(disclosure._digest && claimOfDigest.has(disclosure._digest)
              ? { discloses: claimOfDigest.get(disclosure._digest) }
              : {}),
            salt: disclosure.salt,
            ...(disclosure.key !== undefined ? { name: disclosure.key } : {}),
            value: disclosure.value,
          }
        : { encoded: encodedDisclosures[index] }
    ),
  }
  if (claims) value.claims = claims
  if (keyBinding) value.key_binding = keyBinding

  const facts: [string, string][] = [
    ['Disclosures', `${encodedDisclosures.length}, hashed with ${sdAlg}`],
    ['Key Binding', keyBindingJwt ? 'Key Binding JWT presented' : 'None'],
  ]
  if (isVc && typeof timeSource.vct === 'string') facts.unshift(['Type (vct)', timeSource.vct])

  const signatures: SignatureCheck[] = [jwsSignatureCheck(parts[0], header, options.key, 'Issuer signature')]
  if (keyBindingJwt && keyBinding) {
    const { header: kbHeader } = keyBinding
    const cnf = timeSource.cnf
    signatures.push({
      label: 'Key Binding JWT',
      verify: async () => {
        if (!isRecord(cnf) || !isRecord(cnf.jwk)) {
          return { status: 'unverified', message: 'Not verified: the SD-JWT has no cnf with a jwk to verify it with' }
        }
        let keys: ReturnType<typeof parseKeys>
        try {
          keys = parseKeys(JSON.stringify(cnf.jwk))
        } catch (error) {
          return { status: 'invalid', message: `Invalid: the jwk of cnf cannot be read: ${errorMessage(error)}` }
        }
        return verifyJwsSignature(keyBindingJwt, kbHeader, { keys, source: 'the cnf key of the SD-JWT' })
      },
    })
  }

  return {
    kind: 'sd-jwt',
    title: `${isVc ? 'SD-JWT VC' : 'SD-JWT'}${keyBindingJwt ? ' presentation' : ''}`,
    checks: [
      'RFC 9901 structure and disclosures',
      ...(isVc ? ['SD-JWT VC claims'] : []),
      ...(keyBindingJwt ? ['Key Binding JWT'] : []),
    ],
    notes: [
      ...(keyBindingJwt && !options.nonce?.trim()
        ? ['The nonce of the Key Binding JWT is not compared: give it to do so']
        : []),
      ...(keyBindingJwt && !options.aud?.trim()
        ? ['The aud of the Key Binding JWT is not compared: give it to do so']
        : []),
      ...(isVc ? ['The type metadata of the vct is not fetched', 'The status is not looked up'] : []),
    ],
    value,
    findings,
    facts,
    signatures,
  }
}
