/**
 * LoTE Profiles
 *
 * @see https://www.etsi.org/deliver/etsi_ts/119600_119699/119602/01.01.01_60/ts_119602v010101p.pdf
 * @see https://acceptance.eidas.ec.europa.eu/efda/wallet/lists-of-trusted-entities/mdl-providers
 */

import type z from 'zod'
import { hasDigitalIdentity, LoTEDocumentSchema } from './schemas'
import type { LoTEDocument, PostalAddress, ServiceDigitalIdentity } from './types'

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
  ctx: z.RefinementCtx<LoTEDocument>
) {
  addresses?.forEach((address, index) => {
    if (address.Country.length !== 2) {
      ctx.addIssue({
        code: 'custom',
        message: 'Country must be a 2-letter country code',
        path: [...path, index.toString(), 'Country'],
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
  ctx: z.RefinementCtx<LoTEDocument>
) {
  if (!hasDigitalIdentity(identity)) {
    ctx.addIssue({
      code: 'custom',
      message: 'At least one digital identity type must be provided',
      path,
    })
  }
  identity.X509Certificates?.forEach((certificate, index) => {
    const certificatePath = [...path, 'X509Certificates', index.toString()]
    if (certificate.val === '') {
      ctx.addIssue({ code: 'custom', message: 'A certificate must have a value', path: [...certificatePath, 'val'] })
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
      ctx.addIssue({
        code: 'custom',
        message: 'A public key cannot be a symmetric (oct) key',
        path: [...path, 'PublicKeyValues', index.toString(), 'kty'],
      })
    }
  })
}

/** Every localized string or URI has a language, and a localized string a value. */
function checkLocalizedValues(node: unknown, path: (string | number)[], ctx: z.RefinementCtx<LoTEDocument>) {
  if (Array.isArray(node)) {
    node.forEach((item, index) => {
      checkLocalizedValues(item, [...path, index.toString()], ctx)
    })
    return
  }
  if (node === null || typeof node !== 'object') return
  const record = node as Record<string, unknown>
  if (typeof record.lang === 'string') {
    if (record.lang === '') ctx.addIssue({ code: 'custom', message: 'lang must not be empty', path: [...path, 'lang'] })
    if (record.value === '') {
      ctx.addIssue({ code: 'custom', message: 'value must not be empty', path: [...path, 'value'] })
    }
  }
  for (const [key, value] of Object.entries(record)) {
    // Extensions are free-form: nothing in them is a localized value of this schema
    if (!key.endsWith('Extensions')) checkLocalizedValues(value, [...path, key], ctx)
  }
}

export const LOTE_TYPES = {
  EUPIDProvidersList: 'http://uri.etsi.org/19602/LoTEType/EUPIDProvidersList',
  EUWalletProvidersList: 'http://uri.etsi.org/19602/LoTEType/EUWalletProvidersList',
  EUWRPACProvidersList: 'http://uri.etsi.org/19602/LoTEType/EUWRPACProvidersList',
  EUWRPRCProvidersList: 'http://uri.etsi.org/19602/LoTEType/EUWRPRCProvidersList',
  EUEAAProvidersList: 'http://uri.etsi.org/19602/LoTEType/EUEAAProvidersList',
  EUPubEAAProvidersList: 'http://uri.etsi.org/19602/LoTEType/EUPubEAAProvidersList',
  mDLProvidersList: 'http://trust.ec.europa.eu/lists/mDL/mDLProvidersListType',
} as const

type ListAndSchemeInformationRefinementOptions = {
  loTEType: string
  loTEVersionIdentifier: number
  statusDeterminationApproach: string
  schemeTerritory: string
  schemeTypeCommunityRulesUri: string
  historicalInformationPeriod?: number
  requireNoHistoricalInformationPeriod?: boolean
  requireNoPointersToOtherLoTE?: boolean
}

const listAndSchemeInformationRefinement =
  ({
    loTEType,
    loTEVersionIdentifier,
    statusDeterminationApproach,
    schemeTerritory,
    schemeTypeCommunityRulesUri,
    historicalInformationPeriod,
    requireNoHistoricalInformationPeriod,
    requireNoPointersToOtherLoTE,
  }: ListAndSchemeInformationRefinementOptions) =>
  ({ LoTE }: LoTEDocument, ctx: z.RefinementCtx<LoTEDocument>) => {
    const info = LoTE.ListAndSchemeInformation
    const path = ['LoTE', 'ListAndSchemeInformation']

    if (info.LoTEType !== loTEType) {
      ctx.addIssue({
        code: 'invalid_value',
        values: [loTEType],
        message: `LoTEType must be ${loTEType}`,
        path: [...path, 'LoTEType'],
      })
    }

    if (info.LoTEVersionIdentifier !== loTEVersionIdentifier) {
      ctx.addIssue({
        code: 'invalid_value',
        values: [loTEVersionIdentifier],
        message: `LoTEVersionIdentifier must be ${loTEVersionIdentifier}`,
        path: [...path, 'LoTEVersionIdentifier'],
      })
    }

    if (info.StatusDeterminationApproach !== statusDeterminationApproach) {
      ctx.addIssue({
        code: 'invalid_value',
        values: [statusDeterminationApproach],
        message: `StatusDeterminationApproach must be ${statusDeterminationApproach}`,
        path: [...path, 'StatusDeterminationApproach'],
      })
    }

    if (info.SchemeTerritory !== schemeTerritory) {
      ctx.addIssue({
        code: 'invalid_value',
        values: [schemeTerritory],
        message: `SchemeTerritory must be ${schemeTerritory}`,
        path: [...path, 'SchemeTerritory'],
      })
    }

    if (
      info.SchemeTypeCommunityRules?.length !== 1 ||
      info.SchemeTypeCommunityRules[0].uriValue !== schemeTypeCommunityRulesUri
    ) {
      ctx.addIssue({
        code: 'custom',
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

    if (requireNoPointersToOtherLoTE && typeof info.PointersToOtherLoTE !== 'undefined') {
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
          ctx.addIssue({
            code: 'custom',
            message: 'MimeType must not be empty',
            path: [...pointerPath, 'LoTEQualifiers', qualifierIndex.toString(), 'MimeType'],
          })
        }
      })
    })

    const listIssueDateTime = new Date(info.ListIssueDateTime).getTime()
    const nextUpdate = new Date(info.NextUpdate).getTime()

    if (nextUpdate - listIssueDateTime > SIX_MONTHS_IN_MS) {
      ctx.addIssue({
        code: 'custom',
        message: 'NextUpdate must be within 6 months of ListIssueDateTime',
        path: [...path, 'NextUpdate'],
      })
    }
  }

type TrustedEntitiesListRefinementOptions = {
  allowedServiceTypeIdentifiers: string[]
  informationUriPrefix?: string
}

const trustedEntitiesListRefinement =
  ({ allowedServiceTypeIdentifiers, informationUriPrefix }: TrustedEntitiesListRefinementOptions) =>
  ({ LoTE }: LoTEDocument, ctx: z.RefinementCtx<LoTEDocument>) => {
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
          ctx.addIssue({
            code: 'custom',
            message: `Each TrustedEntityInformation.TEInformationURI must contain at least one URI starting with ${informationUriPrefix}`,
            path: [...trustedEntityPath, 'TrustedEntityInformation', 'TEInformationURI'],
          })
        } else {
          const rest = uri.uriValue.substring(informationUriPrefix.length)
          if (rest.length !== 2) {
            ctx.addIssue({
              code: 'custom',
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

        if (typeof service.ServiceInformation.ServiceStatus !== 'undefined') {
          ctx.addIssue({
            code: 'invalid_type',
            expected: 'undefined',
            message: 'ServiceStatus must not be present',
            path: [...entityServicePath, 'ServiceInformation', 'ServiceStatus'],
          })
        }

        if (typeof service.ServiceInformation.StatusStartingTime !== 'undefined') {
          ctx.addIssue({
            code: 'invalid_type',
            expected: 'undefined',
            message: 'StatusStartingTime must not be present',
            path: [...entityServicePath, 'ServiceInformation', 'StatusStartingTime'],
          })
        }

        if (
          !service.ServiceInformation.ServiceTypeIdentifier ||
          !allowedServiceTypeIdentifiers.includes(service.ServiceInformation.ServiceTypeIdentifier)
        ) {
          ctx.addIssue({
            code: 'invalid_value',
            message: `ServiceTypeIdentifier must be one of the following: ${allowedServiceTypeIdentifiers.join(', ')}`,
            path: [...entityServicePath, 'ServiceInformation', 'ServiceTypeIdentifier'],
            values: allowedServiceTypeIdentifiers,
          })
        }
      })
    })
  }

// ETSI TS 119 602 D
export const EUPIDProvidersListSchema = LoTEDocumentSchema.superRefine(
  listAndSchemeInformationRefinement({
    loTEType: LOTE_TYPES.EUPIDProvidersList,
    loTEVersionIdentifier: 1,
    statusDeterminationApproach: 'http://uri.etsi.org/19602/PIDProvidersList/StatusDetn/EU',
    schemeTerritory: 'EU',
    schemeTypeCommunityRulesUri: 'http://uri.etsi.org/19602/PIDProviders/schemerules/EU',
    requireNoHistoricalInformationPeriod: true,
  })
).superRefine(
  trustedEntitiesListRefinement({
    allowedServiceTypeIdentifiers: [
      'http://uri.etsi.org/19602/SvcType/PID/Issuance',
      'http://uri.etsi.org/19602/SvcType/PID/Revocation',
    ],
    informationUriPrefix: 'http://uri.etsi.org/19602/ListOfTrustedEntities/PIDProvider/',
  })
)

// ETSI TS 119 602 E
export const EUWalletProvidersListSchema = LoTEDocumentSchema.superRefine(
  listAndSchemeInformationRefinement({
    loTEType: LOTE_TYPES.EUWalletProvidersList,
    loTEVersionIdentifier: 1,
    statusDeterminationApproach: 'http://uri.etsi.org/19602/WalletProvidersList/StatusDetn/EU',
    schemeTerritory: 'EU',
    schemeTypeCommunityRulesUri: 'http://uri.etsi.org/19602/WalletProvidersList/schemerules/EU',
    requireNoHistoricalInformationPeriod: true,
  })
).superRefine(
  trustedEntitiesListRefinement({
    allowedServiceTypeIdentifiers: [
      'http://uri.etsi.org/19602/SvcType/WalletSolution/Issuance',
      'http://uri.etsi.org/19602/SvcType/WalletSolution/Revocation',
    ],
    informationUriPrefix: 'http://uri.etsi.org/19602/ListOfTrustedEntities/WalletProvider/',
  })
)

// ETSI TS 119 602 F
export const EUWRPACProvidersListSchema = LoTEDocumentSchema.superRefine(
  listAndSchemeInformationRefinement({
    loTEType: LOTE_TYPES.EUWRPACProvidersList,
    loTEVersionIdentifier: 1,
    statusDeterminationApproach: 'http://uri.etsi.org/19602/WRPACProvidersList/StatusDetn/EU',
    schemeTerritory: 'EU',
    schemeTypeCommunityRulesUri: 'http://uri.etsi.org/19602/WRPACProvidersList/schemerules/EU',
    requireNoHistoricalInformationPeriod: true,
  })
).superRefine(
  trustedEntitiesListRefinement({
    allowedServiceTypeIdentifiers: [
      'http://uri.etsi.org/19602/SvcType/WRPAC/Issuance',
      'http://uri.etsi.org/19602/SvcType/WRPAC/Revocation',
    ],
    informationUriPrefix: 'http://uri.etsi.org/19602/ListOfTrustedEntities/WRPACProvider/',
  })
)

// ETSI TS 119 602 G
export const EUWRPRCProvidersListSchema = LoTEDocumentSchema.superRefine(
  listAndSchemeInformationRefinement({
    loTEType: LOTE_TYPES.EUWRPRCProvidersList,
    loTEVersionIdentifier: 1,
    statusDeterminationApproach: 'http://uri.etsi.org/19602/WRPRCrovidersList/StatusDetn/EU',
    schemeTerritory: 'EU',
    schemeTypeCommunityRulesUri: 'http://uri.etsi.org/19602/WRPRCProvidersList/schemerules/EU',
    requireNoHistoricalInformationPeriod: true,
  })
).superRefine(
  trustedEntitiesListRefinement({
    allowedServiceTypeIdentifiers: [
      'http://uri.etsi.org/19602/SvcType/WRPRC/Issuance',
      'http://uri.etsi.org/19602/SvcType/WRPRC/Revocation',
    ],
    informationUriPrefix: 'http://uri.etsi.org/19602/ListOfTrustedEntities/WRPRCProvider/',
  })
)

export const EUEAAProvidersListSchema = LoTEDocumentSchema.superRefine(
  listAndSchemeInformationRefinement({
    loTEType: LOTE_TYPES.EUEAAProvidersList,
    loTEVersionIdentifier: 1,
    statusDeterminationApproach: 'http://uri.etsi.org/19602/EAAProvidersList/StatusDetn/EU',
    schemeTerritory: 'EU',
    schemeTypeCommunityRulesUri: 'http://uri.etsi.org/19602/EAAProvidersList/schemerules/EU',
    requireNoPointersToOtherLoTE: true,
  })
).superRefine(
  trustedEntitiesListRefinement({
    allowedServiceTypeIdentifiers: [
      'http://uri.etsi.org/19602/SvcType/EAA/Issuance',
      'http://uri.etsi.org/19602/SvcType/EAA/Revocation',
    ],
    informationUriPrefix: 'http://uri.etsi.org/19602/ListOfTrustedEntities/EAAProvider/',
  })
)

// ETSI TS 119 602 H
export const EUPubEAAProvidersListSchema = LoTEDocumentSchema.superRefine(
  listAndSchemeInformationRefinement({
    loTEType: LOTE_TYPES.EUPubEAAProvidersList,
    loTEVersionIdentifier: 1,
    statusDeterminationApproach: 'http://uri.etsi.org/19602/PubEAAProvidersList/StatusDetn/EU',
    schemeTerritory: 'EU',
    schemeTypeCommunityRulesUri: 'http://uri.etsi.org/19602/PubEAAProvidersList/schemerules/EU',
    requireNoPointersToOtherLoTE: true,
    historicalInformationPeriod: 65535,
  })
).superRefine(
  trustedEntitiesListRefinement({
    allowedServiceTypeIdentifiers: [
      'http://uri.etsi.org/19602/SvcType/PubEAA/Issuance',
      'http://uri.etsi.org/19602/SvcType/PubEAA/Revocation',
    ],
    informationUriPrefix: 'http://uri.etsi.org/19602/ListOfTrustedEntities/PubEAAProvider/',
  })
)

// mDL Providers List
export const mDLProvidersListSchema = LoTEDocumentSchema.superRefine(
  listAndSchemeInformationRefinement({
    loTEType: LOTE_TYPES.mDLProvidersList,
    loTEVersionIdentifier: 1,
    statusDeterminationApproach: 'http://trust.ec.europa.eu/lists/mDL/mDLProvidersListStatusDetn',
    schemeTerritory: 'EU',
    schemeTypeCommunityRulesUri: 'http://trust.ec.europa.eu/lists/mDL/schemerules',
  })
).superRefine(
  trustedEntitiesListRefinement({
    allowedServiceTypeIdentifiers: [
      'http://trust.ec.europa.eu/lists/mDL/SvcType/Issuance',
      'http://trust.ec.europa.eu/lists/mDL/SvcType/Revocation',
    ],
  })
)
