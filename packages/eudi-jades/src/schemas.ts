/** Runtime schemas for ETSI TS 119 182-1 V1.2.1 JAdES components. */

import { base64urlDecodeJson, type SchemaValidationCode, type ValidationIssueInput } from '@owf/identity-common'
import { zFlattenedJws, zGeneralJws } from '@owf/jose'
import { z } from 'zod'
import { DETACHED_MECHANISM_IDS } from './constants'
import { addJadesIssue, JADES_VALIDATION_CODES, type JadesValidationCode } from './validation'

type JadesIssueInput = ValidationIssueInput<JadesValidationCode | SchemaValidationCode>

/** A refinement that adds `issue` when `predicate` does not hold */
const check =
  <T>(predicate: (value: T) => boolean, issue: JadesIssueInput) =>
  (value: T, context: z.RefinementCtx) => {
    if (!predicate(value)) addJadesIssue(context, issue)
  }

const notEmpty = (name: string) =>
  check((value: object) => Object.keys(value).length > 0, {
    code: 'too_small',
    message: `${name} must not be empty`,
    context: { minimum: 1, inclusive: true, origin: 'object' },
  })

/** `a` and `b` are present together: an issue at the one that is missing */
function presentTogether(value: Record<string, unknown>, a: string, b: string, context: z.RefinementCtx): void {
  if ((value[a] === undefined) === (value[b] === undefined)) return
  const missing = value[a] === undefined ? a : b
  addJadesIssue(context, {
    code: 'missing_value',
    path: [missing],
    message: `${a} and ${b} must be present together`,
    context: { expected: missing },
  })
}

const BASE64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/
const BASE64URL = /^[A-Za-z0-9_-]+$/
const UTC_SECONDS = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/
const zText = z.string().min(1)
const zDigestAlgorithm = zText.superRefine(
  check((value) => value.toLowerCase() !== 'md5', {
    code: 'invalid_value',
    message: 'MD5 is prohibited by clause 6.2.1',
  })
)
const zBase64 = zText.regex(BASE64, 'Expected a base64-encoded string')
const zBase64Url = zText.regex(BASE64URL, 'Expected an unpadded base64url-encoded string')
const zUri = zText.superRefine(
  check(
    (value) => {
      try {
        return Boolean(new URL(value).protocol)
      } catch {
        return false
      }
    },
    { code: 'invalid_format', message: 'Expected an absolute URI', context: { format: 'uri' } }
  )
)
const zUriReference = zText.superRefine(
  check((value) => !/\s/.test(value), {
    code: 'invalid_format',
    message: 'Expected a URI reference',
    context: { format: 'uri-reference' },
  })
)
const isDateTime = (value: string) => !Number.isNaN(Date.parse(value))
const zDateTime = zText.superRefine(
  check(isDateTime, {
    code: 'invalid_format',
    message: 'Expected an RFC 3339 date-time',
    context: { format: 'date-time' },
  })
)

export const zClaimedSigningTime = z
  .string()
  .regex(UTC_SECONDS, 'Expected an RFC 3339 UTC timestamp without fractional seconds')
  .superRefine(
    check(isDateTime, {
      code: 'invalid_format',
      message: 'Expected a valid date-time',
      context: { format: 'date-time' },
    })
  )

/** JWS algorithm identifier from the IANA JOSE registry. */
export const zSignAlg = zText.superRefine(
  check((value) => value.toLowerCase() !== 'none', { code: 'invalid_value', message: 'alg must identify a signature' })
)

export const zOid = z
  .object({ id: zUri, desc: z.string().optional(), docRefs: z.array(zUri).min(1).optional() })
  .strict()

export const zPkiObject = z.object({ encoding: zUri.optional(), specRef: z.string().optional(), val: zBase64 }).strict()

export const zTstToken = z
  .object({ type: z.string().optional(), encoding: zUri.optional(), specRef: z.string().optional(), val: zBase64 })
  .strict()
export const zTstTokens = z.array(zTstToken).min(1)
export const zTstContainer = z.object({ canonAlg: zUri.optional(), tstTokens: zTstTokens }).strict()
export const zArcTst = zTstContainer
/** sigTst and adoTst shall not contain canonAlg. */
export const zSigTst = z.object({ tstTokens: zTstTokens }).strict()
export const zAdoTst = zSigTst

const zCertificateDigest = z.object({ digAlg: zDigestAlgorithm, digVal: zBase64Url }).strict()
export const zX5tO = zCertificateDigest.superRefine(
  check((value) => value.digAlg.toLowerCase() !== 'sha-256', {
    code: 'invalid_value',
    path: ['digAlg'],
    message: 'x5t#o cannot use sha-256, use x5t#S256',
  })
)

export const zCommitmentReference = z
  .object({
    commId: zOid,
    commQuals: z.array(z.record(z.string(), z.unknown())).min(1).optional(),
  })
  .strict()

export const zSignatureProductionPlace = z
  .object({
    addressCountry: z.string().optional(),
    addressLocality: z.string().optional(),
    addressRegion: z.string().optional(),
    postOfficeBoxNumber: z.string().optional(),
    postalCode: z.string().optional(),
    streetAddress: z.string().optional(),
  })
  .strict()
  .superRefine(notEmpty('sigPl'))

export const zQualifiedArray = z
  .array(z.object({ mediaType: zText, encoding: zText, qVals: z.array(z.unknown()).min(1) }).strict())
  .min(1)

export const zCertifiedAttribute = z.union([
  z.object({ x509AttrCert: zPkiObject }).strict(),
  z.object({ otherAttrCert: zPkiObject }).strict(),
])
export const zSignerAttributes = z
  .object({
    certified: z.array(zCertifiedAttribute).min(1).optional(),
    claimed: zQualifiedArray.optional(),
    signedAssertions: zQualifiedArray.optional(),
  })
  .strict()
  .superRefine(notEmpty('srAts'))

const zUserNotice = z
  .object({
    noticeRef: z
      .object({ organization: z.string(), noticeNumbers: z.array(z.number().int()).min(1) })
      .strict()
      .optional(),
    explText: z.string().optional(),
  })
  .strict()
  .superRefine(notEmpty('spUserNotice'))

export const zSignaturePolicyQualifier = z.union([
  z.object({ spURI: zUri }).strict(),
  z.object({ spUserNotice: zUserNotice }).strict(),
  z.object({ spDSpec: zOid }).strict(),
])

export const zSignaturePolicy = z
  .object({
    id: zOid,
    digAlg: zDigestAlgorithm.optional(),
    digVal: zBase64Url.optional(),
    digPSp: z.boolean().optional(),
    sigPQuals: z.array(zSignaturePolicyQualifier).min(1).optional(),
  })
  .strict()
  .superRefine((value, context) => {
    presentTogether(value, 'digAlg', 'digVal', context)
    if (value.digPSp === true && !value.sigPQuals?.some((qualifier) => 'spDSpec' in qualifier)) {
      addJadesIssue(context, {
        code: 'missing_value',
        path: ['sigPQuals'],
        message: 'sigPId with digPSp=true requires an spDSpec qualifier',
        context: { expected: 'spDSpec' },
      })
    }
  })

export const zSigD = z
  .object({
    mId: zUri,
    pars: z.array(z.string()).min(1),
    hashM: zDigestAlgorithm.optional(),
    hashV: z.array(zBase64Url).min(1).optional(),
    ctys: z.array(z.string()).min(1).optional(),
  })
  .strict()
  .superRefine((value, context) => {
    presentTogether(value, 'hashM', 'hashV', context)
    for (const name of ['hashV', 'ctys'] as const) {
      if (value[name] && value[name].length !== value.pars.length) {
        addJadesIssue(context, {
          code: 'invalid_value',
          path: [name],
          message: `${name} and pars must have equal length`,
        })
      }
    }
    const notAllowed = (names: ReadonlyArray<'hashM' | 'hashV' | 'ctys'>, mechanism: string) => {
      for (const name of names.filter((name) => value[name] !== undefined)) {
        addJadesIssue(context, { code: 'not_allowed', path: [name], message: `${mechanism} must not contain ${name}` })
      }
    }
    if (value.mId === DETACHED_MECHANISM_IDS.httpHeaders) {
      notAllowed(['hashM', 'hashV', 'ctys'], 'HttpHeaders')
      if (value.pars.some((parameter) => parameter !== parameter.toLowerCase())) {
        addJadesIssue(context, {
          code: 'invalid_value',
          path: ['pars'],
          message: 'HTTP header names must be lower-case',
        })
      }
    } else if (value.mId === DETACHED_MECHANISM_IDS.objectByUri) {
      notAllowed(['hashM', 'hashV'], 'ObjectIdByURI')
    } else if (value.mId === DETACHED_MECHANISM_IDS.objectByUriHash && !value.hashM && !value.hashV) {
      addJadesIssue(context, {
        code: 'missing_value',
        path: ['hashV'],
        message: 'ObjectIdByURIHash requires hashM and hashV',
        context: { expected: 'hashV' },
      })
    }
  })

export const zSignaturePolicyStore = z.union([
  z.object({ sigPolDoc: zBase64Url, spDSpec: zOid.optional() }).strict(),
  z.object({ sigPolLocalURI: zUriReference, spDSpec: zOid.optional() }).strict(),
])
export const zCertificateValue = z.union([
  z.object({ x509Cert: zPkiObject }).strict(),
  z.object({ otherCert: zPkiObject }).strict(),
])
export const zXVals = z.array(zCertificateValue).min(1)
export const zRVals = z
  .object({
    crlVals: z.array(zPkiObject).min(1).optional(),
    ocspVals: z.array(zPkiObject).min(1).optional(),
    otherVals: z.array(z.record(z.string(), z.unknown())).min(1).optional(),
  })
  .strict()
  .superRefine(notEmpty('rVals'))
export const zValidationValues = z
  .object({ xVals: zXVals.optional(), rVals: zRVals.optional() })
  .strict()
  .superRefine(notEmpty('Validation values'))

export const zCertId = z
  .object({ digAlg: zDigestAlgorithm, digVal: zBase64Url, kid: zBase64.optional(), x5u: zUriReference.optional() })
  .strict()
export const zXRefs = z.array(zCertId).min(1)
const zCrlReference = z
  .object({
    digAlg: zDigestAlgorithm,
    digVal: zBase64Url,
    crlId: z
      .object({
        issuer: zBase64,
        issueTime: zDateTime,
        number: z.number().optional(),
        uri: zUriReference.optional(),
      })
      .strict()
      .optional(),
  })
  .strict()
const zOcspReference = z
  .object({
    ocspId: z
      .object({
        responderId: z.union([z.object({ byName: zBase64 }).strict(), z.object({ byKey: zBase64 }).strict()]),
        producedAt: zDateTime,
        uri: zUriReference.optional(),
      })
      .strict(),
    digAlg: zDigestAlgorithm,
    digVal: zBase64Url,
  })
  .strict()
export const zRRefs = z
  .object({
    crlRefs: z.array(zCrlReference).min(1).optional(),
    ocspRefs: z.array(zOcspReference).min(1).optional(),
    otherRefs: z.array(z.record(z.string(), z.unknown())).min(1).optional(),
  })
  .strict()
  .superRefine(notEmpty('rRefs'))

const zCanonicalizedTstContainer = zTstContainer.extend({ canonAlg: zUri })
const zNoCanonTstContainer = z.object({ canonAlg: z.never().optional(), tstTokens: zTstTokens }).strict()
const sharedEtsiUInstances = [
  z.object({ sigPSt: zSignaturePolicyStore }).strict(),
  z.object({ sigTst: zSigTst }).strict(),
  z.object({ xVals: zXVals }).strict(),
  z.object({ rVals: zRVals }).strict(),
  z.object({ axVals: zXVals }).strict(),
  z.object({ arVals: zRVals }).strict(),
  z.object({ anyValData: zValidationValues }).strict(),
  z.object({ tstVD: zValidationValues }).strict(),
  z.object({ xRefs: zXRefs }).strict(),
  z.object({ rRefs: zRRefs }).strict(),
  z.object({ axRefs: zXRefs }).strict(),
  z.object({ arRefs: zRRefs }).strict(),
  z.object({ cSig: z.union([zGeneralJws, zFlattenedJws, z.string()]) }).strict(),
] as const
export const zEtsiUClearInstance = z.union([
  ...sharedEtsiUInstances,
  z.object({ arcTst: zCanonicalizedTstContainer }).strict(),
  z.object({ sigRTst: zCanonicalizedTstContainer }).strict(),
  z.object({ rfsTst: zCanonicalizedTstContainer }).strict(),
])
const zEncodedEtsiUInstance = z.union([
  ...sharedEtsiUInstances,
  z.object({ arcTst: zNoCanonTstContainer }).strict(),
  z.object({ sigRTst: zNoCanonTstContainer }).strict(),
  z.object({ rfsTst: zNoCanonTstContainer }).strict(),
])
const zEncodedEtsiU = z
  .array(zBase64Url)
  .min(1)
  .superRefine((items, context) => {
    items.forEach((item, index) => {
      try {
        const result = zEncodedEtsiUInstance.safeParse(base64urlDecodeJson(item))
        if (!result.success)
          addJadesIssue(context, { code: 'invalid_value', path: [index], message: 'Invalid encoded etsiU value' })
      } catch {
        addJadesIssue(context, { code: 'invalid_value', path: [index], message: 'Invalid encoded etsiU JSON value' })
      }
    })
  })
export const zEtsiU = z.union([z.array(zEtsiUClearInstance).min(1), zEncodedEtsiU])
export const zUnprotectedHeader = z.object({ etsiU: zEtsiU }).strict()

const protectedHeaderShape = {
  alg: zSignAlg.optional(),
  cty: z.string().optional(),
  kid: z.string().optional(),
  jku: zUri.optional(),
  jwk: z.record(z.string(), z.unknown()).optional(),
  x5u: zUri.optional(),
  x5c: z.array(zBase64).min(1).optional(),
  x5t: z.never().optional(),
  'x5t#S256': zBase64Url.optional(),
  typ: z.string().optional(),
  crit: z.array(zText).min(1).optional(),
  b64: z.boolean().optional(),
  iat: z.number().int().optional(),
  sigT: zClaimedSigningTime.optional(),
  'x5t#o': zX5tO.optional(),
  sigX5ts: z.array(zCertificateDigest).min(2).optional(),
  srCms: z.array(zCommitmentReference).min(1).optional(),
  sigPl: zSignatureProductionPlace.optional(),
  srAts: zSignerAttributes.optional(),
  adoTst: zAdoTst.optional(),
  sigPId: zSignaturePolicy.optional(),
  sigD: zSigD.optional(),
  etsiU: z.never().optional(),
}
export const zProtectedHeaderParams = z.object(protectedHeaderShape).passthrough()

function refineProtected(
  header: z.infer<typeof zProtectedHeaderParams>,
  context: z.RefinementCtx,
  currentGeneration: boolean
): void {
  const missing = (name: string, message: string, expected: string) =>
    addJadesIssue(context, { code: 'missing_value', path: [name], message, context: { expected } })
  const invalidCrit = (parameter: string, message: string) =>
    addJadesIssue(context, {
      code: JADES_VALIDATION_CODES.INVALID_CRIT,
      path: ['crit'],
      message,
      context: { parameter },
    })

  if (!header.alg) missing('alg', 'alg is required', 'string')
  if (!(header['x5t#S256'] || header.x5c || header['x5t#o'] || header.sigX5ts)) {
    addJadesIssue(context, {
      code: JADES_VALIDATION_CODES.MISSING_CERTIFICATE_REFERENCE,
      message: 'One certificate reference or x5c is required',
    })
  }
  if (currentGeneration) {
    if (header.iat === undefined) missing('iat', 'iat is required for signatures generated now', 'number')
    if (header.sigT !== undefined) {
      addJadesIssue(context, {
        code: 'not_allowed',
        path: ['sigT'],
        message: 'sigT is prohibited for signatures generated on or after 2025-07-15',
      })
    }
  } else if (header.iat === undefined && header.sigT === undefined) {
    missing('iat', 'Exactly one of iat or sigT is required', 'number')
  } else if (header.iat !== undefined && header.sigT !== undefined) {
    addJadesIssue(context, { code: 'not_allowed', path: ['sigT'], message: 'Exactly one of iat or sigT is required' })
  }
  if (header.crit && new Set(header.crit).size !== header.crit.length) {
    invalidCrit(
      header.crit.find((name, index) => header.crit?.indexOf(name) !== index) ?? '',
      'crit entries must be unique'
    )
  }
  const registeredJwsNames = new Set([
    'alg',
    'jku',
    'jwk',
    'kid',
    'x5u',
    'x5c',
    'x5t',
    'x5t#S256',
    'typ',
    'cty',
    'crit',
  ])
  for (const parameter of header.crit ?? []) {
    if (registeredJwsNames.has(parameter) || !(parameter in header)) {
      invalidCrit(parameter, `crit entry ${parameter} must name a present extension header parameter`)
    }
  }
  if (header.b64 !== undefined && !header.crit?.includes('b64')) invalidCrit('b64', 'crit must contain b64')
  if (header.sigD && !header.crit?.includes('sigD')) invalidCrit('sigD', 'crit must contain sigD')
  if (header.sigD?.mId === DETACHED_MECHANISM_IDS.httpHeaders && header.b64 !== false) {
    addJadesIssue(context, {
      code: 'invalid_value',
      path: ['b64'],
      message: 'HttpHeaders requires b64=false',
      context: { allowed: [false] },
    })
  }
}

export const zProtectedHeader = zProtectedHeaderParams.superRefine((header, context) =>
  refineProtected(header, context, false)
)
export const zProtectedHeaderForSigning = zProtectedHeaderParams.superRefine((header, context) =>
  refineProtected(header, context, true)
)
