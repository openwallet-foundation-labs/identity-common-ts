/** Runtime schemas for ETSI TS 119 182-1 V1.2.1 JAdES components. */

import { base64urlDecodeJson } from '@owf/identity-common'
import { z } from 'zod'
import { DETACHED_MECHANISM_IDS } from './constants'

const BASE64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/
const BASE64URL = /^[A-Za-z0-9_-]+$/
const UTC_SECONDS = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/
const zText = z.string().min(1)
const zDigestAlgorithm = zText.refine((value) => value.toLowerCase() !== 'md5', 'MD5 is prohibited by clause 6.2.1')
const zBase64 = zText.regex(BASE64, 'Expected a base64-encoded string')
const zBase64Url = zText.regex(BASE64URL, 'Expected an unpadded base64url-encoded string')
const zUri = zText.refine((value) => {
  try {
    return Boolean(new URL(value).protocol)
  } catch {
    return false
  }
}, 'Expected an absolute URI')
const zUriReference = zText.refine((value) => !/\s/.test(value), 'Expected a URI reference')
const zDateTime = zText.refine((value) => !Number.isNaN(Date.parse(value)), 'Expected an RFC 3339 date-time')

export const zClaimedSigningTime = z
  .string()
  .regex(UTC_SECONDS, 'Expected an RFC 3339 UTC timestamp without fractional seconds')
  .refine((value) => !Number.isNaN(Date.parse(value)), 'Expected a valid date-time')

/** JWS algorithm identifier from the IANA JOSE registry. */
export const zSignAlg = zText.refine((value) => value.toLowerCase() !== 'none', 'alg must identify a signature')

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
export const zX5tO = zCertificateDigest.superRefine((value, context) => {
  if (value.digAlg.toLowerCase() === 'sha-256') {
    context.addIssue({
      code: 'custom',
      path: ['digAlg'],
      message: 'x5t#o cannot use sha-256; use x5t#S256',
    })
  }
})

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
  .refine((value) => Object.keys(value).length > 0, 'sigPl must not be empty')

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
  .refine((value) => Object.keys(value).length > 0, 'srAts must not be empty')

const zUserNotice = z
  .object({
    noticeRef: z
      .object({ organization: z.string(), noticeNumbers: z.array(z.number().int()).min(1) })
      .strict()
      .optional(),
    explText: z.string().optional(),
  })
  .strict()
  .refine((value) => Object.keys(value).length > 0, 'spUserNotice must not be empty')

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
    if ((value.digAlg === undefined) !== (value.digVal === undefined)) {
      context.addIssue({ code: 'custom', message: 'sigPId digAlg and digVal must be present together' })
    }
    if (value.digPSp === true && !value.sigPQuals?.some((qualifier) => 'spDSpec' in qualifier)) {
      context.addIssue({
        code: 'custom',
        path: ['sigPQuals'],
        message: 'sigPId with digPSp=true requires an spDSpec qualifier',
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
    if ((value.hashM === undefined) !== (value.hashV === undefined)) {
      context.addIssue({ code: 'custom', message: 'sigD hashM and hashV must be present together' })
    }
    if (value.hashV && value.hashV.length !== value.pars.length) {
      context.addIssue({ code: 'custom', path: ['hashV'], message: 'hashV and pars must have equal length' })
    }
    if (value.ctys && value.ctys.length !== value.pars.length) {
      context.addIssue({ code: 'custom', path: ['ctys'], message: 'ctys and pars must have equal length' })
    }
    if (value.mId === DETACHED_MECHANISM_IDS.httpHeaders) {
      if (value.hashM || value.hashV || value.ctys) {
        context.addIssue({ code: 'custom', message: 'HttpHeaders must not contain hashM, hashV, or ctys' })
      }
      if (value.pars.some((parameter) => parameter !== parameter.toLowerCase())) {
        context.addIssue({ code: 'custom', path: ['pars'], message: 'HTTP header names must be lower-case' })
      }
    } else if (value.mId === DETACHED_MECHANISM_IDS.objectByUri) {
      if (value.hashM || value.hashV) {
        context.addIssue({ code: 'custom', message: 'ObjectIdByURI must not contain hashM or hashV' })
      }
    } else if (value.mId === DETACHED_MECHANISM_IDS.objectByUriHash && (!value.hashM || !value.hashV)) {
      context.addIssue({ code: 'custom', message: 'ObjectIdByURIHash requires hashM and hashV' })
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
  .refine((value) => Object.keys(value).length > 0, 'rVals must not be empty')
export const zValidationValues = z
  .object({ xVals: zXVals.optional(), rVals: zRVals.optional() })
  .strict()
  .refine((value) => Object.keys(value).length > 0, 'Validation values must not be empty')

export const zCertId = z
  .object({ digAlg: zDigestAlgorithm, digVal: zBase64Url, kid: zBase64.optional(), x5u: zUriReference.optional() })
  .strict()
export const zXRefs = z.array(zCertId).min(1)
const zCRLReference = z
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
const zOCSPReference = z
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
    crlRefs: z.array(zCRLReference).min(1).optional(),
    ocspRefs: z.array(zOCSPReference).min(1).optional(),
    otherRefs: z.array(z.record(z.string(), z.unknown())).min(1).optional(),
  })
  .strict()
  .refine((value) => Object.keys(value).length > 0, 'rRefs must not be empty')

export const zJwsSignature = z
  .object({
    protected: zBase64Url.optional(),
    header: z.record(z.string(), z.unknown()).optional(),
    signature: zBase64Url,
  })
  .strict()
export const zGeneralJws = z
  .object({ payload: z.string().optional(), signatures: z.array(zJwsSignature).min(1) })
  .strict()
export const zFlattenedJws = z
  .object({
    protected: zBase64Url.optional(),
    header: z.record(z.string(), z.unknown()).optional(),
    payload: z.string().optional(),
    signature: zBase64Url,
  })
  .strict()
export const zCompactJws = z.object({ protected: zBase64Url, payload: z.string(), signature: zBase64Url }).strict()

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
        if (!result.success) context.addIssue({ code: 'custom', path: [index], message: 'Invalid encoded etsiU value' })
      } catch {
        context.addIssue({ code: 'custom', path: [index], message: 'Invalid encoded etsiU JSON value' })
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
  if (!header.alg) context.addIssue({ code: 'custom', path: ['alg'], message: 'alg is required' })
  if (!(header['x5t#S256'] || header.x5c || header['x5t#o'] || header.sigX5ts)) {
    context.addIssue({ code: 'custom', message: 'One certificate reference or x5c is required' })
  }
  if (currentGeneration) {
    if (header.iat === undefined) {
      context.addIssue({ code: 'custom', path: ['iat'], message: 'iat is required for signatures generated now' })
    }
    if (header.sigT !== undefined) {
      context.addIssue({
        code: 'custom',
        path: ['sigT'],
        message: 'sigT is prohibited for signatures generated on or after 2025-07-15',
      })
    }
  } else if ((header.iat === undefined) === (header.sigT === undefined)) {
    context.addIssue({ code: 'custom', message: 'Exactly one of iat or sigT is required' })
  }
  if (header.crit && new Set(header.crit).size !== header.crit.length) {
    context.addIssue({ code: 'custom', path: ['crit'], message: 'crit entries must be unique' })
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
      context.addIssue({
        code: 'custom',
        path: ['crit'],
        message: `crit entry ${parameter} must name a present extension header parameter`,
      })
    }
  }
  if (header.b64 !== undefined && !header.crit?.includes('b64')) {
    context.addIssue({ code: 'custom', path: ['crit'], message: 'crit must contain b64' })
  }
  if (header.sigD && !header.crit?.includes('sigD')) {
    context.addIssue({ code: 'custom', path: ['crit'], message: 'crit must contain sigD' })
  }
  if (header.sigD?.mId === DETACHED_MECHANISM_IDS.httpHeaders && header.b64 !== false) {
    context.addIssue({ code: 'custom', path: ['b64'], message: 'HttpHeaders requires b64=false' })
  }
}

export const zProtectedHeader = zProtectedHeaderParams.superRefine((header, context) =>
  refineProtected(header, context, false)
)
export const zProtectedHeaderForSigning = zProtectedHeaderParams.superRefine((header, context) =>
  refineProtected(header, context, true)
)

export const zSignOptions = z.object({
  alg: zSignAlg,
  kid: z.string().optional(),
  certificates: z.array(z.string()).optional(),
})
export const zVerifyOptions = z.object({
  detachedPayload: z.union([z.string(), z.instanceof(Uint8Array)]).optional(),
  signatureIndex: z.number().int().nonnegative().optional(),
  understoodCriticalParameters: z.array(zText).optional(),
})
