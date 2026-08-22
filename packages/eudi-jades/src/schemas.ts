/** Runtime schemas for ETSI TS 119 182-1 V1.2.1 JAdES components. */

import { base64urlDecode } from '@owf/identity-common'
import { z } from 'zod'
import { DETACHED_MECHANISM_IDS } from './constants'

const BASE64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/
const BASE64URL = /^[A-Za-z0-9_-]+$/
const UTC_SECONDS = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/
const text = z.string().min(1)
const digestAlgorithm = text.refine((value) => value.toLowerCase() !== 'md5', 'MD5 is prohibited by clause 6.2.1')
const b64 = text.regex(BASE64, 'Expected a base64-encoded string')
const b64u = text.regex(BASE64URL, 'Expected an unpadded base64url-encoded string')
const uri = text.refine((value) => {
  try {
    return Boolean(new URL(value).protocol)
  } catch {
    return false
  }
}, 'Expected an absolute URI')
const uriReference = text.refine((value) => !/\s/.test(value), 'Expected a URI reference')
const dateTime = text.refine((value) => !Number.isNaN(Date.parse(value)), 'Expected an RFC 3339 date-time')

export const ClaimedSigningTimeSchema = z
  .string()
  .regex(UTC_SECONDS, 'Expected an RFC 3339 UTC timestamp without fractional seconds')
  .refine((value) => !Number.isNaN(Date.parse(value)), 'Expected a valid date-time')

/** JWS algorithm identifier from the IANA JOSE registry. */
export const SignAlgSchema = text.refine((value) => value.toLowerCase() !== 'none', 'alg must identify a signature')

export const OIdSchema = z
  .object({ id: uri, desc: z.string().optional(), docRefs: z.array(uri).min(1).optional() })
  .strict()

export const PkiObjectSchema = z.object({ encoding: uri.optional(), specRef: z.string().optional(), val: b64 }).strict()

export const TstTokenSchema = z
  .object({ type: z.string().optional(), encoding: uri.optional(), specRef: z.string().optional(), val: b64 })
  .strict()
export const TstTokensSchema = z.array(TstTokenSchema).min(1)
export const TstContainerSchema = z.object({ canonAlg: uri.optional(), tstTokens: TstTokensSchema }).strict()
export const ArcTstSchema = TstContainerSchema
/** sigTst and adoTst shall not contain canonAlg. */
export const SigTstSchema = z.object({ tstTokens: TstTokensSchema }).strict()
export const AdoTstSchema = SigTstSchema

const CertificateDigestSchema = z.object({ digAlg: digestAlgorithm, digVal: b64u }).strict()
export const X5tOSchema = CertificateDigestSchema.superRefine((value, context) => {
  if (value.digAlg.toLowerCase() === 'sha-256') {
    context.addIssue({
      code: 'custom',
      path: ['digAlg'],
      message: 'x5t#o cannot use sha-256; use x5t#S256',
    })
  }
})

export const CommitmentReferenceSchema = z
  .object({
    commId: OIdSchema,
    commQuals: z.array(z.record(z.string(), z.unknown())).min(1).optional(),
  })
  .strict()

export const SignatureProductionPlaceSchema = z
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

export const QualifiedArraySchema = z
  .array(z.object({ mediaType: text, encoding: text, qVals: z.array(z.unknown()).min(1) }).strict())
  .min(1)

export const CertifiedAttributeSchema = z.union([
  z.object({ x509AttrCert: PkiObjectSchema }).strict(),
  z.object({ otherAttrCert: PkiObjectSchema }).strict(),
])
export const SignerAttributesSchema = z
  .object({
    certified: z.array(CertifiedAttributeSchema).min(1).optional(),
    claimed: QualifiedArraySchema.optional(),
    signedAssertions: QualifiedArraySchema.optional(),
  })
  .strict()
  .refine((value) => Object.keys(value).length > 0, 'srAts must not be empty')

const UserNoticeSchema = z
  .object({
    noticeRef: z
      .object({ organization: z.string(), noticeNumbers: z.array(z.number().int()).min(1) })
      .strict()
      .optional(),
    explText: z.string().optional(),
  })
  .strict()
  .refine((value) => Object.keys(value).length > 0, 'spUserNotice must not be empty')

export const SignaturePolicyQualifierSchema = z.union([
  z.object({ spURI: uri }).strict(),
  z.object({ spUserNotice: UserNoticeSchema }).strict(),
  z.object({ spDSpec: OIdSchema }).strict(),
])

export const SignaturePolicySchema = z
  .object({
    id: OIdSchema,
    digAlg: digestAlgorithm.optional(),
    digVal: b64u.optional(),
    digPSp: z.boolean().optional(),
    sigPQuals: z.array(SignaturePolicyQualifierSchema).min(1).optional(),
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

export const SigDSchema = z
  .object({
    mId: uri,
    pars: z.array(z.string()).min(1),
    hashM: digestAlgorithm.optional(),
    hashV: z.array(b64u).min(1).optional(),
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

export const SignaturePolicyStoreSchema = z.union([
  z.object({ sigPolDoc: b64u, spDSpec: OIdSchema.optional() }).strict(),
  z.object({ sigPolLocalURI: uriReference, spDSpec: OIdSchema.optional() }).strict(),
])
export const CertificateValueSchema = z.union([
  z.object({ x509Cert: PkiObjectSchema }).strict(),
  z.object({ otherCert: PkiObjectSchema }).strict(),
])
export const XValsSchema = z.array(CertificateValueSchema).min(1)
export const RValsSchema = z
  .object({
    crlVals: z.array(PkiObjectSchema).min(1).optional(),
    ocspVals: z.array(PkiObjectSchema).min(1).optional(),
    otherVals: z.array(z.record(z.string(), z.unknown())).min(1).optional(),
  })
  .strict()
  .refine((value) => Object.keys(value).length > 0, 'rVals must not be empty')
export const ValidationValuesSchema = z
  .object({ xVals: XValsSchema.optional(), rVals: RValsSchema.optional() })
  .strict()
  .refine((value) => Object.keys(value).length > 0, 'Validation values must not be empty')

export const CertIdSchema = z
  .object({ digAlg: digestAlgorithm, digVal: b64u, kid: b64.optional(), x5u: uriReference.optional() })
  .strict()
export const XRefsSchema = z.array(CertIdSchema).min(1)
const CRLReferenceSchema = z
  .object({
    digAlg: digestAlgorithm,
    digVal: b64u,
    crlId: z
      .object({
        issuer: b64,
        issueTime: dateTime,
        number: z.number().optional(),
        uri: uriReference.optional(),
      })
      .strict()
      .optional(),
  })
  .strict()
const OCSPReferenceSchema = z
  .object({
    ocspId: z
      .object({
        responderId: z.union([z.object({ byName: b64 }).strict(), z.object({ byKey: b64 }).strict()]),
        producedAt: dateTime,
        uri: uriReference.optional(),
      })
      .strict(),
    digAlg: digestAlgorithm,
    digVal: b64u,
  })
  .strict()
export const RRefsSchema = z
  .object({
    crlRefs: z.array(CRLReferenceSchema).min(1).optional(),
    ocspRefs: z.array(OCSPReferenceSchema).min(1).optional(),
    otherRefs: z.array(z.record(z.string(), z.unknown())).min(1).optional(),
  })
  .strict()
  .refine((value) => Object.keys(value).length > 0, 'rRefs must not be empty')

export const JWSSignatureSchema = z
  .object({
    protected: b64u.optional(),
    header: z.record(z.string(), z.unknown()).optional(),
    signature: b64u,
  })
  .strict()
export const GeneralJWSSchema = z
  .object({ payload: z.string().optional(), signatures: z.array(JWSSignatureSchema).min(1) })
  .strict()
export const FlattenedJWSSchema = z
  .object({
    protected: b64u.optional(),
    header: z.record(z.string(), z.unknown()).optional(),
    payload: z.string().optional(),
    signature: b64u,
  })
  .strict()
export const CompactJWSSchema = z.object({ protected: b64u, payload: z.string(), signature: b64u }).strict()

const CanonicalizedTstContainerSchema = TstContainerSchema.extend({ canonAlg: uri })
const NoCanonTstContainerSchema = z.object({ canonAlg: z.never().optional(), tstTokens: TstTokensSchema }).strict()
const sharedEtsiUInstances = [
  z.object({ sigPSt: SignaturePolicyStoreSchema }).strict(),
  z.object({ sigTst: SigTstSchema }).strict(),
  z.object({ xVals: XValsSchema }).strict(),
  z.object({ rVals: RValsSchema }).strict(),
  z.object({ axVals: XValsSchema }).strict(),
  z.object({ arVals: RValsSchema }).strict(),
  z.object({ anyValData: ValidationValuesSchema }).strict(),
  z.object({ tstVD: ValidationValuesSchema }).strict(),
  z.object({ xRefs: XRefsSchema }).strict(),
  z.object({ rRefs: RRefsSchema }).strict(),
  z.object({ axRefs: XRefsSchema }).strict(),
  z.object({ arRefs: RRefsSchema }).strict(),
  z.object({ cSig: z.union([GeneralJWSSchema, FlattenedJWSSchema, z.string()]) }).strict(),
] as const
export const EtsiUClearInstanceSchema = z.union([
  ...sharedEtsiUInstances,
  z.object({ arcTst: CanonicalizedTstContainerSchema }).strict(),
  z.object({ sigRTst: CanonicalizedTstContainerSchema }).strict(),
  z.object({ rfsTst: CanonicalizedTstContainerSchema }).strict(),
])
const EncodedEtsiUInstanceSchema = z.union([
  ...sharedEtsiUInstances,
  z.object({ arcTst: NoCanonTstContainerSchema }).strict(),
  z.object({ sigRTst: NoCanonTstContainerSchema }).strict(),
  z.object({ rfsTst: NoCanonTstContainerSchema }).strict(),
])
const EncodedEtsiUSchema = z
  .array(b64u)
  .min(1)
  .superRefine((items, context) => {
    items.forEach((item, index) => {
      try {
        const result = EncodedEtsiUInstanceSchema.safeParse(JSON.parse(base64urlDecode(item)))
        if (!result.success) context.addIssue({ code: 'custom', path: [index], message: 'Invalid encoded etsiU value' })
      } catch {
        context.addIssue({ code: 'custom', path: [index], message: 'Invalid encoded etsiU JSON value' })
      }
    })
  })
export const EtsiUSchema = z.union([z.array(EtsiUClearInstanceSchema).min(1), EncodedEtsiUSchema])
export const UnprotectedHeaderSchema = z.object({ etsiU: EtsiUSchema }).strict()

const protectedHeaderShape = {
  alg: SignAlgSchema.optional(),
  cty: z.string().optional(),
  kid: z.string().optional(),
  jku: uri.optional(),
  jwk: z.record(z.string(), z.unknown()).optional(),
  x5u: uri.optional(),
  x5c: z.array(b64).min(1).optional(),
  x5t: z.never().optional(),
  'x5t#S256': b64u.optional(),
  typ: z.string().optional(),
  crit: z.array(text).min(1).optional(),
  b64: z.boolean().optional(),
  iat: z.number().int().optional(),
  sigT: ClaimedSigningTimeSchema.optional(),
  'x5t#o': X5tOSchema.optional(),
  sigX5ts: z.array(CertificateDigestSchema).min(2).optional(),
  srCms: z.array(CommitmentReferenceSchema).min(1).optional(),
  sigPl: SignatureProductionPlaceSchema.optional(),
  srAts: SignerAttributesSchema.optional(),
  adoTst: AdoTstSchema.optional(),
  sigPId: SignaturePolicySchema.optional(),
  sigD: SigDSchema.optional(),
  etsiU: z.never().optional(),
}
export const ProtectedHeaderParamsSchema = z.object(protectedHeaderShape).passthrough()

function refineProtected(
  header: z.infer<typeof ProtectedHeaderParamsSchema>,
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

export const ProtectedHeaderSchema = ProtectedHeaderParamsSchema.superRefine((header, context) =>
  refineProtected(header, context, false)
)
export const ProtectedHeaderForSigningSchema = ProtectedHeaderParamsSchema.superRefine((header, context) =>
  refineProtected(header, context, true)
)

export const SignOptionsSchema = z.object({
  alg: SignAlgSchema,
  kid: z.string().optional(),
  certificates: z.array(z.string()).optional(),
})
export const VerifyOptionsSchema = z.object({
  detachedPayload: z.union([z.string(), z.instanceof(Uint8Array)]).optional(),
  signatureIndex: z.number().int().nonnegative().optional(),
  understoodCriticalParameters: z.array(text).optional(),
})
