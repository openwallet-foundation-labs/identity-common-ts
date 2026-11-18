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

import { addValidationIssue } from '@owf/identity-common'
import { z } from 'zod'

// ============================================================================
// Localized Value Schemas
// ============================================================================

export const zLocalizedString = z.object({
  lang: z.string(),
  value: z.string(),
})

export const zLocalizedUri = z.object({
  lang: z.string(),
  uriValue: z.url(),
})

// ============================================================================
// Address Schemas
// ============================================================================

export const zPostalAddress = z.object({
  lang: z.string(),
  StreetAddress: z.string(),
  Locality: z.string().optional(),
  StateOrProvince: z.string().optional(),
  PostalCode: z.string().optional(),
  // A plain string in the JSON schema; the EU profiles require an ISO 3166-1 alpha-2 code
  Country: z.string(),
})

export const zSchemeOperatorAddress = z.object({
  SchemeOperatorPostalAddress: z.array(zPostalAddress),
  SchemeOperatorElectronicAddress: z.array(zLocalizedUri),
})

export const zTrustedEntityAddress = z.object({
  TEPostalAddress: z.array(zPostalAddress),
  TEElectronicAddress: z.array(zLocalizedUri),
})

// ============================================================================
// Digital Identity Schemas
// ============================================================================

export const zPkiObject = z.object({
  encoding: z.url().optional(),
  specRef: z.string().optional(),
  val: z.string(),
})

/**
 * An X509Certificates entry: the JSON schema's `pkiOb`. The usual values are `encoding`
 * `urn:ietf:params:tls-cert-type:x509` and `specRef` `RFC5280`, but any URI and string are allowed.
 */
export const zX509CertificateRef = zPkiObject

export const zJwkPublicKey = z.looseObject({
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
export const zServiceDigitalIdentity = z.object({
  X509Certificates: z.array(zX509CertificateRef).optional(),
  X509SubjectNames: z.array(z.string()).optional(),
  PublicKeyValues: z.array(zJwkPublicKey).optional(),
  X509SKIs: z.array(z.string()).optional(),
  OtherIds: z.array(z.string()).optional(),
})

/** Whether a ServiceDigitalIdentity carries at least one identity of any kind */
export function hasDigitalIdentity(id: z.infer<typeof zServiceDigitalIdentity>): boolean {
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

/**
 * The time of an RFC 3339 date-time in milliseconds since the epoch, NaN if it is not one.
 * Read from its fields, as `Date.parse` gives NaN for a leap second and need not accept a
 * lowercase `t` or `z`; a leap second counts as the first second of the next minute.
 */
export function rfc3339DateTimeToMs(value: string): number {
  const match = isRfc3339DateTime(value) ? RFC3339_DATE_TIME.exec(value) : null
  if (!match) return Number.NaN
  const [year, month, day, hour, minute, second] = match.slice(1, 7).map(Number)
  const offsetMinutes =
    match[8] === undefined ? 0 : (match[8] === '-' ? -1 : 1) * (Number(match[9]) * 60 + Number(match[10]))
  const date = new Date(0)
  // setUTCFullYear keeps years 0 to 99, which Date.UTC maps to 1900 to 1999; fields past their range carry over
  date.setUTCFullYear(year, month - 1, day)
  date.setUTCHours(hour, minute - offsetMinutes, second, Number(`0${match[7] ?? ''}`) * 1000)
  return date.getTime()
}

const zDateTime = z.string().superRefine((value, ctx) => {
  if (isRfc3339DateTime(value)) return
  addValidationIssue(ctx, {
    code: 'invalid_format',
    message: 'Invalid RFC 3339 date-time',
    context: { format: 'RFC 3339 date-time' },
  })
})

// ============================================================================
// Service Schemas
// ============================================================================

export const zServiceSupplyPoint = z.object({
  ServiceType: z.string().optional(),
  uriValue: z.url(),
})

export const zServiceInformation = z.object({
  ServiceName: z.array(zLocalizedString).min(1),
  ServiceDigitalIdentity: zServiceDigitalIdentity,
  ServiceTypeIdentifier: z.url().optional(),
  ServiceStatus: z.url().optional(),
  StatusStartingTime: zDateTime.optional(),
  SchemeServiceDefinitionURI: z.array(zLocalizedUri).optional(),
  ServiceSupplyPoints: z.array(zServiceSupplyPoint).optional(),
  ServiceDefinitionURI: z.array(zLocalizedUri).optional(),
  ServiceInformationExtensions: z.array(z.unknown()).optional(),
})

export const zServiceHistoryInstance = z.object({
  ServiceName: z.array(zLocalizedString).min(1),
  ServiceDigitalIdentity: zServiceDigitalIdentity,
  ServiceStatus: z.url(),
  StatusStartingTime: zDateTime,
  ServiceTypeIdentifier: z.url().optional(),
  ServiceInformationExtensions: z.array(z.unknown()).optional(),
})

export const zTrustedEntityService = z.object({
  ServiceInformation: zServiceInformation,
  ServiceHistory: z.array(zServiceHistoryInstance).optional(),
})

// ============================================================================
// Trusted Entity Schemas
// ============================================================================

export const zTrustedEntityInformation = z.object({
  TEName: z.array(zLocalizedString).min(1),
  TETradeName: z.array(zLocalizedString).optional(),
  TEAddress: zTrustedEntityAddress,
  TEInformationURI: z.array(zLocalizedUri).optional(),
  TEInformationExtensions: z.array(z.unknown()).optional(),
})

export const zTrustedEntity = z.object({
  TrustedEntityInformation: zTrustedEntityInformation,
  TrustedEntityServices: z.array(zTrustedEntityService).min(1),
})

// ============================================================================
// List and Scheme Information Schemas
// ============================================================================

export const zPolicyOrLegalNotice = z.object({
  LoTEPolicy: zLocalizedUri.optional(),
  // The JSON schema of TS 119 602 types LoTELegalNotice as a plain string, the XML schema as a multilingual string
  LoTELegalNotice: z.union([z.string(), zLocalizedString]).optional(),
})

/**
 * PolicyOrLegalNotice as the JSON schema's `oneOf` has it: exactly one of "every item
 * has a LoTEPolicy" and "every item has a LoTELegalNotice" holds. So a list of policies,
 * or a list of legal notices, possibly with the other key on some items but not on all;
 * not an empty list, not a list where every item has both.
 */
export const zPolicyOrLegalNoticeList = z.array(zPolicyOrLegalNotice).superRefine((items, ctx) => {
  const policies = items.every((item) => item.LoTEPolicy !== undefined)
  const notices = items.every((item) => item.LoTELegalNotice !== undefined)
  if (policies !== notices) return
  if (policies) {
    if (items.length === 0) {
      addValidationIssue(ctx, {
        code: 'too_small',
        message: 'PolicyOrLegalNotice needs at least one item',
        context: { minimum: 1, inclusive: true, origin: 'array' },
      })
    } else {
      addValidationIssue(ctx, {
        code: 'invalid_value',
        message: 'PolicyOrLegalNotice cannot have both LoTEPolicy and LoTELegalNotice on every item',
        context: {},
      })
    }
    return
  }
  // Neither holds: the kind of the first item that has one sets what the others lack
  const first = items.find((item) => item.LoTEPolicy !== undefined || item.LoTELegalNotice !== undefined)
  const key = first?.LoTEPolicy !== undefined ? 'LoTEPolicy' : 'LoTELegalNotice'
  items.forEach((item, index) => {
    if (item[key] === undefined) {
      addValidationIssue(ctx, {
        code: 'missing_value',
        message: first
          ? `Every item has a LoTEPolicy, or every item has a LoTELegalNotice: this one has no ${key}`
          : 'An item needs LoTEPolicy or LoTELegalNotice',
        path: [index],
        context: { expected: first ? key : 'LoTEPolicy or LoTELegalNotice' },
      })
    }
  })
})

export const zLoteQualifier = z.object({
  LoTEType: z.url(),
  SchemeOperatorName: z.array(zLocalizedString).min(1),
  SchemeTypeCommunityRules: z.array(zLocalizedUri).optional(),
  SchemeTerritory: z.string().length(2).optional(),
  MimeType: z.string(),
})

export const zOtherLotePointer = z.object({
  LoTELocation: z.url(),
  ServiceDigitalIdentities: z.array(zServiceDigitalIdentity).min(1),
  LoTEQualifiers: z.array(zLoteQualifier).min(1),
})

export const zListAndSchemeInformation = z.object({
  LoTEVersionIdentifier: z.number().int(),
  LoTESequenceNumber: z.number().int(),
  LoTEType: z.url().optional(),
  SchemeOperatorName: z.array(zLocalizedString).min(1),
  SchemeOperatorAddress: zSchemeOperatorAddress.optional(),
  SchemeName: z.array(zLocalizedString).optional(),
  SchemeInformationURI: z.array(zLocalizedUri).optional(),
  StatusDeterminationApproach: z.url().optional(),
  SchemeTypeCommunityRules: z.array(zLocalizedUri).optional(),
  SchemeTerritory: z.string().length(2).optional(),
  PolicyOrLegalNotice: zPolicyOrLegalNoticeList.optional(),
  HistoricalInformationPeriod: z.number().optional(),
  PointersToOtherLoTE: z.array(zOtherLotePointer).optional(),
  ListIssueDateTime: zDateTime,
  NextUpdate: zDateTime,
  DistributionPoints: z.array(z.url()).optional(),
  SchemeExtensions: z.array(z.unknown()).optional(),
})

// ============================================================================
// LoTE Root Schemas
// ============================================================================

export const zLote = z.object({
  ListAndSchemeInformation: zListAndSchemeInformation,
  TrustedEntitiesList: z.array(zTrustedEntity).optional(),
})

export const zLoteDocument = z.object({
  LoTE: zLote,
})

/**
 * The `PolicyOrLegalNotice` that lists in use publish: a `LoTELegalNotice` that is an array of
 * localized URIs, and items that carry both keys (the German EUDI Wallet sandbox lists).
 */
export const zCompatPolicyOrLegalNoticeList = z
  .array(
    zPolicyOrLegalNotice
      .extend({
        LoTELegalNotice: z.union([z.string(), zLocalizedString, z.array(zLocalizedUri)]).optional(),
      })
      .superRefine((item, ctx) => {
        if (item.LoTEPolicy !== undefined || item.LoTELegalNotice !== undefined) return
        addValidationIssue(ctx, {
          code: 'missing_value',
          message: 'An item needs LoTEPolicy or LoTELegalNotice',
          context: { expected: 'LoTEPolicy or LoTELegalNotice' },
        })
      })
  )
  .min(1)

/** `zLoteDocument` with the `PolicyOrLegalNotice` of `zCompatPolicyOrLegalNoticeList` */
export const zCompatLoteDocument = zLoteDocument.extend({
  LoTE: zLote.extend({
    ListAndSchemeInformation: zListAndSchemeInformation.extend({
      PolicyOrLegalNotice: zCompatPolicyOrLegalNoticeList.optional(),
    }),
  }),
})
