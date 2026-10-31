/**
 * LoTE Zod Schemas
 *
 * Zod schemas for ETSI TS 119 602 (LoTE - List of Trusted Entities) format.
 * Types are derived from these schemas via z.infer<>.
 *
 * They follow the TS 119 602 v1.1.1 JSON schema (1960201_json_schema.json, vendored
 * under src/__tests__/etsi-ts-119-602/ and compared with these schemas by
 * schema-drift.test.mts, which also lists the remaining differences). Rules the EU
 * lists add (2-letter countries, at least one digital identity per service, non-empty
 * names, and so on) live in the profiles, not here.
 *
 * @see https://www.etsi.org/deliver/etsi_ts/119600_119699/119602/01.01.01_60/ts_119602v010101p.pdf
 * @see https://forge.etsi.org/rep/esi/x19_60201_lists_of_trusted_entities
 */

import { z } from 'zod'

// ============================================================================
// Localized Value Schemas
// ============================================================================

export const LocalizedStringSchema = z.object({
  lang: z.string(),
  value: z.string(),
})

export const LocalizedURISchema = z.object({
  lang: z.string(),
  uriValue: z.url(),
})

// ============================================================================
// Address Schemas
// ============================================================================

export const PostalAddressSchema = z.object({
  lang: z.string(),
  StreetAddress: z.string(),
  Locality: z.string().optional(),
  StateOrProvince: z.string().optional(),
  PostalCode: z.string().optional(),
  // A plain string in the JSON schema; the EU profiles require an ISO 3166-1 alpha-2 code
  Country: z.string(),
})

export const SchemeOperatorAddressSchema = z.object({
  SchemeOperatorPostalAddress: z.array(PostalAddressSchema),
  SchemeOperatorElectronicAddress: z.array(LocalizedURISchema),
})

export const TrustedEntityAddressSchema = z.object({
  TEPostalAddress: z.array(PostalAddressSchema),
  TEElectronicAddress: z.array(LocalizedURISchema),
})

// ============================================================================
// Digital Identity Schemas
// ============================================================================

export const PkiObjectSchema = z.object({
  encoding: z.url().optional(),
  specRef: z.string().optional(),
  val: z.string(),
})

/**
 * An X509Certificates entry: the JSON schema's `pkiOb`. The usual values are `encoding`
 * `urn:ietf:params:tls-cert-type:x509` and `specRef` `RFC5280`, but any URI and string are allowed.
 */
export const X509CertificateRefSchema = PkiObjectSchema

export const JWKPublicKeySchema = z.looseObject({
  // RFC 7517 as the JSON schema references it lists EC, RSA and oct; OKP (RFC 8037) is accepted too
  kty: z.enum(['RSA', 'EC', 'OKP', 'oct']),
  kid: z.string().optional(),
  use: z.enum(['sig', 'enc']).optional(),
  alg: z.string().optional(),
})

/**
 * The JSON schema requires none of the identity kinds (`{}` validates); the EU profiles
 * require at least one (`hasDigitalIdentity`).
 */
export const ServiceDigitalIdentitySchema = z.object({
  X509Certificates: z.array(X509CertificateRefSchema).optional(),
  X509SubjectNames: z.array(z.string()).optional(),
  PublicKeyValues: z.array(JWKPublicKeySchema).optional(),
  X509SKIs: z.array(z.string()).optional(),
  OtherIds: z.array(z.string()).optional(),
})

/** Whether a ServiceDigitalIdentity carries at least one identity of any kind */
export function hasDigitalIdentity(id: z.infer<typeof ServiceDigitalIdentitySchema>): boolean {
  return Boolean(
    id.X509Certificates?.length ||
      id.X509SubjectNames?.length ||
      id.PublicKeyValues?.length ||
      id.X509SKIs?.length ||
      id.OtherIds?.length
  )
}

const RFC3339_DATE_TIME = /^(\d{4})-(\d{2})-(\d{2})[Tt](\d{2}):(\d{2}):(\d{2})(\.\d+)?(?:[Zz]|([+-])(\d{2}):(\d{2}))$/

/**
 * An RFC 3339 date-time, the JSON schema's `format: date-time`: `Z` or an offset,
 * either case for `T` and `Z`, and a leap second at 23:59:60 UTC.
 */
export function isRfc3339DateTime(value: string): boolean {
  const match = RFC3339_DATE_TIME.exec(value)
  if (!match) return false
  const [year, month, day, hour, minute, second] = match.slice(1, 7).map(Number)
  const leapYear = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0)
  const days = [31, leapYear ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31][month - 1]
  if (days === undefined || day < 1 || day > days || hour > 23 || minute > 59 || second > 60) return false
  const offsetHours = match[9] === undefined ? 0 : Number(match[9])
  const offsetMinutes = match[10] === undefined ? 0 : Number(match[10])
  if (offsetHours > 23 || offsetMinutes > 59) return false
  if (second === 60) {
    // A leap second exists only at 23:59:60 UTC
    const sign = match[8] === '-' ? -1 : 1
    const utcMinutes = (((hour * 60 + minute - sign * (offsetHours * 60 + offsetMinutes)) % 1440) + 1440) % 1440
    return utcMinutes === 23 * 60 + 59
  }
  return true
}

const DateTimeSchema = z.string().refine(isRfc3339DateTime, { message: 'Invalid RFC 3339 date-time' })

// ============================================================================
// Service Schemas
// ============================================================================

export const ServiceSupplyPointSchema = z.object({
  ServiceType: z.string().optional(),
  uriValue: z.url(),
})

export const ServiceInformationSchema = z.object({
  ServiceName: z.array(LocalizedStringSchema).min(1),
  ServiceDigitalIdentity: ServiceDigitalIdentitySchema,
  ServiceTypeIdentifier: z.url().optional(),
  ServiceStatus: z.url().optional(),
  StatusStartingTime: DateTimeSchema.optional(),
  SchemeServiceDefinitionURI: z.array(LocalizedURISchema).optional(),
  ServiceSupplyPoints: z.array(ServiceSupplyPointSchema).optional(),
  ServiceDefinitionURI: z.array(LocalizedURISchema).optional(),
  ServiceInformationExtensions: z.array(z.unknown()).optional(),
})

export const ServiceHistoryInstanceSchema = z.object({
  ServiceName: z.array(LocalizedStringSchema).min(1),
  ServiceDigitalIdentity: ServiceDigitalIdentitySchema,
  ServiceStatus: z.url(),
  StatusStartingTime: DateTimeSchema,
  ServiceTypeIdentifier: z.url().optional(),
  ServiceInformationExtensions: z.array(z.unknown()).optional(),
})

export const TrustedEntityServiceSchema = z.object({
  ServiceInformation: ServiceInformationSchema,
  ServiceHistory: z.array(ServiceHistoryInstanceSchema).optional(),
})

// ============================================================================
// Trusted Entity Schemas
// ============================================================================

export const TrustedEntityInformationSchema = z.object({
  TEName: z.array(LocalizedStringSchema).min(1),
  TETradeName: z.array(LocalizedStringSchema).optional(),
  TEAddress: TrustedEntityAddressSchema,
  TEInformationURI: z.array(LocalizedURISchema).optional(),
  TEInformationExtensions: z.array(z.unknown()).optional(),
})

export const TrustedEntitySchema = z.object({
  TrustedEntityInformation: TrustedEntityInformationSchema,
  TrustedEntityServices: z.array(TrustedEntityServiceSchema).min(1),
})

// ============================================================================
// List and Scheme Information Schemas
// ============================================================================

export const PolicyOrLegalNoticeSchema = z.object({
  LoTEPolicy: LocalizedURISchema.optional(),
  // The JSON schema of TS 119 602 types LoTELegalNotice as a plain string, the XML schema as a multilingual string
  LoTELegalNotice: z.union([z.string(), LocalizedStringSchema]).optional(),
})

/**
 * PolicyOrLegalNotice as the JSON schema's `oneOf` has it: exactly one of "every item
 * has a LoTEPolicy" and "every item has a LoTELegalNotice" holds. So a list of policies,
 * or a list of legal notices, possibly with the other key on some items but not on all;
 * not an empty list, not a list where every item has both.
 */
export const PolicyOrLegalNoticeListSchema = z.array(PolicyOrLegalNoticeSchema).superRefine((items, ctx) => {
  const policies = items.every((item) => item.LoTEPolicy !== undefined)
  const notices = items.every((item) => item.LoTELegalNotice !== undefined)
  if (policies !== notices) return
  if (policies) {
    ctx.addIssue({
      code: 'custom',
      message:
        items.length === 0
          ? 'PolicyOrLegalNotice needs at least one item'
          : 'PolicyOrLegalNotice cannot have both LoTEPolicy and LoTELegalNotice on every item',
      path: [],
    })
    return
  }
  // Neither holds: the kind of the first item that has one sets what the others lack
  const first = items.find((item) => item.LoTEPolicy !== undefined || item.LoTELegalNotice !== undefined)
  const key = first?.LoTEPolicy !== undefined ? 'LoTEPolicy' : 'LoTELegalNotice'
  items.forEach((item, index) => {
    if (item[key] === undefined) {
      ctx.addIssue({
        code: 'custom',
        message: first
          ? `Every item has a LoTEPolicy, or every item has a LoTELegalNotice: this one has no ${key}`
          : 'An item needs LoTEPolicy or LoTELegalNotice',
        path: [index],
      })
    }
  })
})

export const LoTEQualifierSchema = z.object({
  LoTEType: z.url(),
  SchemeOperatorName: z.array(LocalizedStringSchema).min(1),
  SchemeTypeCommunityRules: z.array(LocalizedURISchema).optional(),
  SchemeTerritory: z.string().length(2).optional(),
  MimeType: z.string(),
})

export const OtherLoTEPointerSchema = z.object({
  LoTELocation: z.url(),
  ServiceDigitalIdentities: z.array(ServiceDigitalIdentitySchema).min(1),
  LoTEQualifiers: z.array(LoTEQualifierSchema).min(1),
})

export const ListAndSchemeInformationSchema = z.object({
  LoTEVersionIdentifier: z.number().int(),
  LoTESequenceNumber: z.number().int(),
  LoTEType: z.url().optional(),
  SchemeOperatorName: z.array(LocalizedStringSchema).min(1),
  SchemeOperatorAddress: SchemeOperatorAddressSchema.optional(),
  SchemeName: z.array(LocalizedStringSchema).optional(),
  SchemeInformationURI: z.array(LocalizedURISchema).optional(),
  StatusDeterminationApproach: z.url().optional(),
  SchemeTypeCommunityRules: z.array(LocalizedURISchema).optional(),
  SchemeTerritory: z.string().length(2).optional(),
  PolicyOrLegalNotice: PolicyOrLegalNoticeListSchema.optional(),
  HistoricalInformationPeriod: z.number().optional(),
  PointersToOtherLoTE: z.array(OtherLoTEPointerSchema).optional(),
  ListIssueDateTime: DateTimeSchema,
  NextUpdate: DateTimeSchema,
  DistributionPoints: z.array(z.url()).optional(),
  SchemeExtensions: z.array(z.unknown()).optional(),
})

// ============================================================================
// LoTE Root Schemas
// ============================================================================

export const LoTESchema = z.object({
  ListAndSchemeInformation: ListAndSchemeInformationSchema,
  TrustedEntitiesList: z.array(TrustedEntitySchema).optional(),
})

export const LoTEDocumentSchema = z.object({
  LoTE: LoTESchema,
})
