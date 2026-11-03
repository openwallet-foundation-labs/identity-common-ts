/**
 * LoTE Profiles
 *
 * @see https://www.etsi.org/deliver/etsi_ts/119600_119699/119602/01.01.01_60/ts_119602v010101p.pdf
 * @see https://acceptance.eidas.ec.europa.eu/efda/wallet/lists-of-trusted-entities/mdl-providers
 */

import { addValidationIssue } from '@owf/identity-common'
import { z } from 'zod'
import { LoteError } from './lote-error'
import {
  hasDigitalIdentity,
  rfc3339DateTimeToMs,
  type zCompatLoteDocument,
  zCompatPolicyOrLegalNoticeList,
  zListAndSchemeInformation,
  zLote,
  zLoteDocument,
  zPolicyOrLegalNoticeList,
  zServiceInformation,
  zTrustedEntity,
  zTrustedEntityService,
} from './schemas'
import type { PostalAddress, ServiceDigitalIdentity } from './types'
import type { LoteValidationCode } from './validator'

/** The context of an empty string where the profile needs a value */
const NON_EMPTY_STRING = { minimum: 1, inclusive: true, origin: 'string' }

/**
 * `strict` validates a list exactly as ETSI TS 119 602 defines it. `compat` also accepts the
 * deviations of lists in use that don't change who is trusted (see `validateLoteProfile`).
 */
export type LoteValidationMode = 'strict' | 'compat'

/** Options of `validateLoteProfile` */
export interface LoteProfileValidationOptions<M extends LoteValidationMode = LoteValidationMode> {
  /** Defaults to `strict` */
  mode?: M
  /**
   * Compat mode only. The `SchemeTerritory` values to accept. Defaults to `['EU']`, which the
   * profiles require (TS 119 602 D to I). Pass e.g. `['DE']` to accept a national list of an EU type.
   */
  allowedTerritories?: M extends 'compat' ? readonly string[] : never
}

// What the profile refinements read, in strict and in compat mode
type LoteDocument = z.output<typeof zCompatLoteDocument>

const SIX_MONTHS_IN_MS = 6 * 31 * 24 * 60 * 60 * 1000

/*
 * What the profiles require beyond the TS 119 602 JSON schema, which the base schema
 * follows. These were base-schema rules before it followed the JSON schema; the EU lists
 * keep them.
 */

/** A postal address names its country by a 2-letter code. */
function checkCountries(
  addresses: PostalAddress[] | undefined,
  path: (string | number)[],
  ctx: z.RefinementCtx<LoteDocument>
) {
  addresses?.forEach((address, index) => {
    if (address.Country.length !== 2) {
      addValidationIssue(ctx, {
        code: 'invalid_format',
        message: 'Country must be a 2-letter country code',
        path: [...path, index.toString(), 'Country'],
        context: { format: 'ISO 3166-1 alpha-2' },
      })
    }
  })
}

const X509_ENCODING = 'urn:ietf:params:tls-cert-type:x509'
const X509_SPEC_REF = 'RFC5280'

/**
 * A service digital identity carries at least one identity; a certificate has a value
 * and, when it names them, the X.509 encoding and RFC 5280; a public key is not a
 * symmetric (`oct`) key.
 */
function checkDigitalIdentity(
  identity: ServiceDigitalIdentity,
  path: (string | number)[],
  ctx: z.RefinementCtx<LoteDocument>
) {
  if (!hasDigitalIdentity(identity)) {
    addValidationIssue(ctx, { code: 'missing', message: 'At least one digital identity type must be provided', path })
  }
  identity.X509Certificates?.forEach((certificate, index) => {
    const certificatePath = [...path, 'X509Certificates', index.toString()]
    if (certificate.val === '') {
      addValidationIssue(ctx, {
        code: 'too_small',
        message: 'A certificate must have a value',
        path: [...certificatePath, 'val'],
        context: NON_EMPTY_STRING,
      })
    }
    if (certificate.encoding !== undefined && certificate.encoding !== X509_ENCODING) {
      ctx.addIssue({
        code: 'invalid_value',
        values: [X509_ENCODING],
        message: `A certificate's encoding must be ${X509_ENCODING}`,
        path: [...certificatePath, 'encoding'],
      })
    }
    if (certificate.specRef !== undefined && certificate.specRef !== X509_SPEC_REF) {
      ctx.addIssue({
        code: 'invalid_value',
        values: [X509_SPEC_REF],
        message: `A certificate's specRef must be ${X509_SPEC_REF}`,
        path: [...certificatePath, 'specRef'],
      })
    }
  })
  identity.PublicKeyValues?.forEach((key, index) => {
    if (key.kty === 'oct') {
      addValidationIssue(ctx, {
        code: 'invalid_value',
        context: {},
        message: 'A public key cannot be a symmetric (oct) key',
        path: [...path, 'PublicKeyValues', index.toString(), 'kty'],
      })
    }
  })
}

/** Every localized string or URI has a language, and a localized string a value. */
function checkLocalizedValues(node: unknown, path: (string | number)[], ctx: z.RefinementCtx<LoteDocument>) {
  if (Array.isArray(node)) {
    node.forEach((item, index) => {
      checkLocalizedValues(item, [...path, index.toString()], ctx)
    })
    return
  }
  if (node === null || typeof node !== 'object') return
  const record = node as Record<string, unknown>
  if (typeof record.lang === 'string') {
    if (record.lang === '') {
      addValidationIssue(ctx, {
        code: 'too_small',
        message: 'lang must not be empty',
        path: [...path, 'lang'],
        context: NON_EMPTY_STRING,
      })
    }
    if (record.value === '') {
      addValidationIssue(ctx, {
        code: 'too_small',
        message: 'value must not be empty',
        path: [...path, 'value'],
        context: NON_EMPTY_STRING,
      })
    }
  }
  for (const [key, value] of Object.entries(record)) {
    // Extensions are free-form: nothing in them is a localized value of this schema
    if (!key.endsWith('Extensions')) checkLocalizedValues(value, [...path, key], ctx)
  }
}

export const LOTE_TYPES = {
  EuPidProvidersList: 'http://uri.etsi.org/19602/LoTEType/EUPIDProvidersList',
  EuWalletProvidersList: 'http://uri.etsi.org/19602/LoTEType/EUWalletProvidersList',
  EuWrpacProvidersList: 'http://uri.etsi.org/19602/LoTEType/EUWRPACProvidersList',
  EuWrprcProvidersList: 'http://uri.etsi.org/19602/LoTEType/EUWRPRCProvidersList',
  EuEaaProvidersList: 'http://uri.etsi.org/19602/LoTEType/EUEAAProvidersList',
  EuPubEaaProvidersList: 'http://uri.etsi.org/19602/LoTEType/EUPubEAAProvidersList',
  MdlProvidersList: 'http://trust.ec.europa.eu/lists/mDL/mDLProvidersListType',
} as const

type ListAndSchemeInformationRefinementOptions = {
  loteType: string
  loteVersionIdentifier: number
  statusDeterminationApproach: string
  allowedTerritories?: readonly string[]
  schemeTypeCommunityRulesUri: string
  historicalInformationPeriod?: number
  requireNoHistoricalInformationPeriod?: boolean
  requireNoPointersToOtherLote?: boolean
}

const listAndSchemeInformationRefinement =
  ({
    allowedTerritories = ['EU'],
    schemeTypeCommunityRulesUri,
    historicalInformationPeriod,
    requireNoHistoricalInformationPeriod,
    requireNoPointersToOtherLote,
  }: ListAndSchemeInformationRefinementOptions) =>
  ({ LoTE }: LoteDocument, ctx: z.RefinementCtx<LoteDocument>) => {
    const info = LoTE.ListAndSchemeInformation
    const path = ['LoTE', 'ListAndSchemeInformation']

    if (info.SchemeTerritory === undefined || !allowedTerritories.includes(info.SchemeTerritory)) {
      ctx.addIssue({
        code: 'invalid_value',
        values: [...allowedTerritories],
        message: `SchemeTerritory must be ${allowedTerritories.join(' or ')}`,
        path: [...path, 'SchemeTerritory'],
      })
    }

    if (
      info.SchemeTypeCommunityRules?.length !== 1 ||
      info.SchemeTypeCommunityRules[0].uriValue !== schemeTypeCommunityRulesUri
    ) {
      addValidationIssue(ctx, {
        code: 'invalid_value',
        context: {},
        message: `SchemeTypeCommunityRules must contain a single element with uriValue of ${schemeTypeCommunityRulesUri}`,
        path: [...path, 'SchemeTypeCommunityRules'],
      })
    }

    if (requireNoHistoricalInformationPeriod && typeof info.HistoricalInformationPeriod !== 'undefined') {
      ctx.addIssue({
        code: 'invalid_type',
        expected: 'undefined',
        message: 'HistoricalInformationPeriod must not be present',
        path: [...path, 'HistoricalInformationPeriod'],
      })
    }

    if (historicalInformationPeriod !== undefined && info.HistoricalInformationPeriod !== historicalInformationPeriod) {
      ctx.addIssue({
        code: 'invalid_value',
        values: [historicalInformationPeriod],
        message: `HistoricalInformationPeriod must be ${historicalInformationPeriod}`,
        path: [...path, 'HistoricalInformationPeriod'],
      })
    }

    if (requireNoPointersToOtherLote && typeof info.PointersToOtherLoTE !== 'undefined') {
      ctx.addIssue({
        code: 'invalid_type',
        expected: 'undefined',
        message: 'PointersToOtherLoTE must not be present',
        path: [...path, 'PointersToOtherLoTE'],
      })
    }

    checkLocalizedValues(info, path, ctx)
    checkCountries(
      info.SchemeOperatorAddress?.SchemeOperatorPostalAddress,
      [...path, 'SchemeOperatorAddress', 'SchemeOperatorPostalAddress'],
      ctx
    )
    info.PointersToOtherLoTE?.forEach((pointer, pointerIndex) => {
      const pointerPath = [...path, 'PointersToOtherLoTE', pointerIndex.toString()]
      pointer.ServiceDigitalIdentities.forEach((identity, identityIndex) => {
        checkDigitalIdentity(identity, [...pointerPath, 'ServiceDigitalIdentities', identityIndex.toString()], ctx)
      })
      pointer.LoTEQualifiers.forEach((qualifier, qualifierIndex) => {
        if (qualifier.MimeType === '') {
          addValidationIssue(ctx, {
            code: 'too_small',
            context: NON_EMPTY_STRING,
            message: 'MimeType must not be empty',
            path: [...pointerPath, 'LoTEQualifiers', qualifierIndex.toString(), 'MimeType'],
          })
        }
      })
    })

    // Not new Date(): its NaN for a leap second would let any NextUpdate through
    const listIssueDateTime = rfc3339DateTimeToMs(info.ListIssueDateTime)
    const nextUpdate = rfc3339DateTimeToMs(info.NextUpdate)

    if (nextUpdate - listIssueDateTime > SIX_MONTHS_IN_MS) {
      addValidationIssue<LoteValidationCode>(ctx, {
        code: 'next_update_too_late',
        message: 'NextUpdate must be within 6 months of ListIssueDateTime',
        path: [...path, 'NextUpdate'],
      })
    }
  }

type TrustedEntitiesListRefinementOptions = {
  serviceTypeIdentifiers: readonly [string, ...string[]]
  informationUriPrefix?: string
  /** The ServiceStatus schema of the profile in each mode */
  serviceStatus: Record<LoteValidationMode, z.ZodType<string | undefined>>
}

const trustedEntitiesListRefinement =
  ({ informationUriPrefix }: TrustedEntitiesListRefinementOptions) =>
  ({ LoTE }: LoteDocument, ctx: z.RefinementCtx<LoteDocument>) => {
    LoTE.TrustedEntitiesList?.forEach((entity, index) => {
      const trustedEntityPath = ['LoTE', 'TrustedEntitiesList', index.toString()]

      checkLocalizedValues(entity, trustedEntityPath, ctx)
      checkCountries(
        entity.TrustedEntityInformation.TEAddress.TEPostalAddress,
        [...trustedEntityPath, 'TrustedEntityInformation', 'TEAddress', 'TEPostalAddress'],
        ctx
      )

      if (informationUriPrefix) {
        const uri = entity.TrustedEntityInformation.TEInformationURI?.find(({ uriValue }) =>
          uriValue.startsWith(informationUriPrefix)
        )

        if (!uri) {
          addValidationIssue(ctx, {
            code: 'missing',
            message: `Each TrustedEntityInformation.TEInformationURI must contain at least one URI starting with ${informationUriPrefix}`,
            path: [...trustedEntityPath, 'TrustedEntityInformation', 'TEInformationURI'],
          })
        } else {
          const rest = uri.uriValue.substring(informationUriPrefix.length)
          if (rest.length !== 2) {
            addValidationIssue(ctx, {
              code: 'invalid_format',
              context: { format: `${informationUriPrefix} followed by an ISO 3166-1 alpha-2 country code` },
              message: `URI starting with ${informationUriPrefix} must be followed by a 2-letter country code`,
              path: [...trustedEntityPath, 'TrustedEntityInformation', 'TEInformationURI'],
            })
          }
        }
      }

      entity.TrustedEntityServices.forEach((service, serviceIndex) => {
        const entityServicePath = [...trustedEntityPath, 'TrustedEntityServices', serviceIndex.toString()]

        checkDigitalIdentity(
          service.ServiceInformation.ServiceDigitalIdentity,
          [...entityServicePath, 'ServiceInformation', 'ServiceDigitalIdentity'],
          ctx
        )
        service.ServiceHistory?.forEach((instance, historyIndex) => {
          checkDigitalIdentity(
            instance.ServiceDigitalIdentity,
            [...entityServicePath, 'ServiceHistory', historyIndex.toString(), 'ServiceDigitalIdentity'],
            ctx
          )
        })

        // The schema has checked ServiceStatus against the profile
        if (
          service.ServiceInformation.StatusStartingTime !== undefined &&
          service.ServiceInformation.ServiceStatus === undefined
        ) {
          ctx.addIssue({
            code: 'invalid_type',
            expected: 'undefined',
            message: 'StatusStartingTime must not be present',
            path: [...entityServicePath, 'ServiceInformation', 'StatusStartingTime'],
          })
        }
      })
    })
  }

type ProfileDefinition = {
  list: Omit<ListAndSchemeInformationRefinementOptions, 'allowedTerritories'>
  entities: TrustedEntitiesListRefinementOptions
}

const serviceStatusOneOf = <const T extends readonly [string, ...string[]]>(statuses: T) =>
  z.enum(statuses, {
    error: ({ input }) =>
      input === undefined
        ? 'ServiceStatus must be present'
        : `ServiceStatus must be one of the following: ${statuses.join(', ')}`,
  })

const zNoServiceStatus = z.undefined({ error: 'ServiceStatus must not be present' }).optional()
const withoutServiceStatus = { strict: zNoServiceStatus, compat: zNoServiceStatus }

// ETSI TS 119 602 H
const pubEaaServiceStatus = serviceStatusOneOf([
  'http://uri.etsi.org/19602/PubEAAProvidersList/SvcStatus/notified',
  'http://uri.etsi.org/19602/PubEAAProvidersList/SvcStatus/withdrawn',
])

export const profileDefinitions = {
  // ETSI TS 119 602 D
  EuPidProvidersList: {
    list: {
      loteType: LOTE_TYPES.EuPidProvidersList,
      loteVersionIdentifier: 1,
      statusDeterminationApproach: 'http://uri.etsi.org/19602/PIDProvidersList/StatusDetn/EU',
      schemeTypeCommunityRulesUri: 'http://uri.etsi.org/19602/PIDProviders/schemerules/EU',
      requireNoHistoricalInformationPeriod: true,
    },
    entities: {
      serviceTypeIdentifiers: [
        'http://uri.etsi.org/19602/SvcType/PID/Issuance',
        'http://uri.etsi.org/19602/SvcType/PID/Revocation',
      ],
      informationUriPrefix: 'http://uri.etsi.org/19602/ListOfTrustedEntities/PIDProvider/',
      serviceStatus: {
        strict: zNoServiceStatus,
        // The German PID Providers List sets this status, which no profile defines
        compat: serviceStatusOneOf(['http://uri.etsi.org/19602/PidProvidersList/SvcStatus/notified']).optional(),
      },
    },
  },

  // ETSI TS 119 602 E
  EuWalletProvidersList: {
    list: {
      loteType: LOTE_TYPES.EuWalletProvidersList,
      loteVersionIdentifier: 1,
      statusDeterminationApproach: 'http://uri.etsi.org/19602/WalletProvidersList/StatusDetn/EU',
      schemeTypeCommunityRulesUri: 'http://uri.etsi.org/19602/WalletProvidersList/schemerules/EU',
      requireNoHistoricalInformationPeriod: true,
    },
    entities: {
      serviceTypeIdentifiers: [
        'http://uri.etsi.org/19602/SvcType/WalletSolution/Issuance',
        'http://uri.etsi.org/19602/SvcType/WalletSolution/Revocation',
      ],
      informationUriPrefix: 'http://uri.etsi.org/19602/ListOfTrustedEntities/WalletProvider/',
      serviceStatus: withoutServiceStatus,
    },
  },

  // ETSI TS 119 602 F
  EuWrpacProvidersList: {
    list: {
      loteType: LOTE_TYPES.EuWrpacProvidersList,
      loteVersionIdentifier: 1,
      statusDeterminationApproach: 'http://uri.etsi.org/19602/WRPACProvidersList/StatusDetn/EU',
      schemeTypeCommunityRulesUri: 'http://uri.etsi.org/19602/WRPACProvidersList/schemerules/EU',
      requireNoHistoricalInformationPeriod: true,
    },
    entities: {
      serviceTypeIdentifiers: [
        'http://uri.etsi.org/19602/SvcType/WRPAC/Issuance',
        'http://uri.etsi.org/19602/SvcType/WRPAC/Revocation',
      ],
      informationUriPrefix: 'http://uri.etsi.org/19602/ListOfTrustedEntities/WRPACProvider/',
      serviceStatus: withoutServiceStatus,
    },
  },

  // ETSI TS 119 602 G
  EuWrprcProvidersList: {
    list: {
      loteType: LOTE_TYPES.EuWrprcProvidersList,
      loteVersionIdentifier: 1,
      statusDeterminationApproach: 'http://uri.etsi.org/19602/WRPRCrovidersList/StatusDetn/EU',
      schemeTypeCommunityRulesUri: 'http://uri.etsi.org/19602/WRPRCProvidersList/schemerules/EU',
      requireNoHistoricalInformationPeriod: true,
    },
    entities: {
      serviceTypeIdentifiers: [
        'http://uri.etsi.org/19602/SvcType/WRPRC/Issuance',
        'http://uri.etsi.org/19602/SvcType/WRPRC/Revocation',
      ],
      informationUriPrefix: 'http://uri.etsi.org/19602/ListOfTrustedEntities/WRPRCProvider/',
      serviceStatus: withoutServiceStatus,
    },
  },

  EuEaaProvidersList: {
    list: {
      loteType: LOTE_TYPES.EuEaaProvidersList,
      loteVersionIdentifier: 1,
      statusDeterminationApproach: 'http://uri.etsi.org/19602/EAAProvidersList/StatusDetn/EU',
      schemeTypeCommunityRulesUri: 'http://uri.etsi.org/19602/EAAProvidersList/schemerules/EU',
      requireNoPointersToOtherLote: true,
    },
    entities: {
      serviceTypeIdentifiers: [
        'http://uri.etsi.org/19602/SvcType/EAA/Issuance',
        'http://uri.etsi.org/19602/SvcType/EAA/Revocation',
      ],
      informationUriPrefix: 'http://uri.etsi.org/19602/ListOfTrustedEntities/EAAProvider/',
      serviceStatus: withoutServiceStatus,
    },
  },

  // ETSI TS 119 602 H
  EuPubEaaProvidersList: {
    list: {
      loteType: LOTE_TYPES.EuPubEaaProvidersList,
      loteVersionIdentifier: 1,
      statusDeterminationApproach: 'http://uri.etsi.org/19602/PubEAAProvidersList/StatusDetn/EU',
      schemeTypeCommunityRulesUri: 'http://uri.etsi.org/19602/PubEAAProvidersList/schemerules/EU',
      requireNoPointersToOtherLote: true,
      historicalInformationPeriod: 65535,
    },
    entities: {
      serviceTypeIdentifiers: [
        'http://uri.etsi.org/19602/SvcType/PubEAA/Issuance',
        'http://uri.etsi.org/19602/SvcType/PubEAA/Revocation',
      ],
      informationUriPrefix: 'http://uri.etsi.org/19602/ListOfTrustedEntities/PubEAAProvider/',
      // A withdrawn Pub-EAA provider stays listed: only a notified one is trusted
      serviceStatus: {
        strict: pubEaaServiceStatus,
        compat: pubEaaServiceStatus,
      },
    },
  },

  // mDL Providers List
  MdlProvidersList: {
    list: {
      loteType: LOTE_TYPES.MdlProvidersList,
      loteVersionIdentifier: 1,
      statusDeterminationApproach: 'http://trust.ec.europa.eu/lists/mDL/mDLProvidersListStatusDetn',
      schemeTypeCommunityRulesUri: 'http://trust.ec.europa.eu/lists/mDL/schemerules',
    },
    entities: {
      serviceTypeIdentifiers: [
        'http://trust.ec.europa.eu/lists/mDL/SvcType/Issuance',
        'http://trust.ec.europa.eu/lists/mDL/SvcType/Revocation',
      ],
      serviceStatus: withoutServiceStatus,
    },
  },
} as const satisfies Record<keyof typeof LOTE_TYPES, ProfileDefinition>

const policyOrLegalNoticeSchemas = {
  strict: zPolicyOrLegalNoticeList.optional(),
  compat: zCompatPolicyOrLegalNoticeList.optional(),
}

/**
 * The schema of a profile in a mode. The rules that narrow a type (LoTEType, ServiceTypeIdentifier,
 * ServiceStatus, and so on) are part of the shape, so the output type of the schema has them.
 */
export const createProfileSchema = <const D extends ProfileDefinition, M extends LoteValidationMode = 'strict'>(
  { list, entities }: D,
  { mode = 'strict' as M, allowedTerritories }: LoteProfileValidationOptions<M> = {}
) => {
  if (mode !== 'compat' && allowedTerritories) {
    throw new LoteError('allowedTerritories only applies in compat mode')
  }
  const serviceTypeIdentifiers = entities.serviceTypeIdentifiers as D['entities']['serviceTypeIdentifiers']
  const service = zTrustedEntityService.extend({
    ServiceInformation: zServiceInformation.extend({
      ServiceTypeIdentifier: z.enum(serviceTypeIdentifiers, {
        error: `ServiceTypeIdentifier must be one of the following: ${serviceTypeIdentifiers.join(', ')}`,
      }),
      ServiceStatus: entities.serviceStatus[mode] as D['entities']['serviceStatus'][M],
    }),
  })

  return zLoteDocument
    .extend({
      LoTE: zLote.extend({
        ListAndSchemeInformation: zListAndSchemeInformation.extend({
          LoTEType: z.literal(list.loteType as D['list']['loteType'], { error: `LoTEType must be ${list.loteType}` }),
          LoTEVersionIdentifier: z.literal(list.loteVersionIdentifier as D['list']['loteVersionIdentifier'], {
            error: `LoTEVersionIdentifier must be ${list.loteVersionIdentifier}`,
          }),
          StatusDeterminationApproach: z.literal(
            list.statusDeterminationApproach as D['list']['statusDeterminationApproach'],
            { error: `StatusDeterminationApproach must be ${list.statusDeterminationApproach}` }
          ),
          PolicyOrLegalNotice: policyOrLegalNoticeSchemas[mode],
        }),
        TrustedEntitiesList: z
          .array(zTrustedEntity.extend({ TrustedEntityServices: z.array(service).min(1) }))
          .optional(),
      }),
    })
    .superRefine(listAndSchemeInformationRefinement({ ...list, allowedTerritories }))
    .superRefine(trustedEntitiesListRefinement(entities))
}

export const zEuPidProvidersList = createProfileSchema(profileDefinitions.EuPidProvidersList)
export const zEuWalletProvidersList = createProfileSchema(profileDefinitions.EuWalletProvidersList)
export const zEuWrpacProvidersList = createProfileSchema(profileDefinitions.EuWrpacProvidersList)
export const zEuWrprcProvidersList = createProfileSchema(profileDefinitions.EuWrprcProvidersList)
export const zEuEaaProvidersList = createProfileSchema(profileDefinitions.EuEaaProvidersList)
export const zEuPubEaaProvidersList = createProfileSchema(profileDefinitions.EuPubEaaProvidersList)
export const zMdlProvidersList = createProfileSchema(profileDefinitions.MdlProvidersList)
