import { readFileSync } from 'node:fs'
import { decodeJwt } from '@owf/identity-common'
import Ajv from 'ajv'
import addFormats from 'ajv-formats'
import { describe, expect, it } from 'vitest'
import { validateLoTE } from '../index'
import type { LoTEDocument } from '../types'
import {
  EUPIDProvidersJWT,
  LP26PIDProvidersEmptyJWT,
  LP26WRPRCProvidersEmptyJWT,
  WalletProvidersJWT,
  WRPACProvidersJWT,
} from './fixtures.mjs'

/**
 * `validateLoTE` against the ETSI TS 119 602 v1.1.1 JSON schema (vendored unchanged in
 * ./etsi-ts-119-602), run over the same documents. Both must agree on the documents
 * below, and fail at the same place when they reject one. Where `validateLoTE` knowingly
 * differs from the schema, looser or stricter, the case is listed with its reason, so a
 * change in either direction shows up here.
 */

const BASE = 'https://forge.etsi.org/rep/esi/x19_60201_lists_of_trusted_entities/1960201_json_schema/'
const read = (path: string) => JSON.parse(readFileSync(new URL(`./etsi-ts-119-602/${path}`, import.meta.url), 'utf8'))

// strict: false, as the schema carries `contentEncoding` and an `additionalProperties` inside `properties`
const ajv = new Ajv({ strict: false, allErrors: true })
addFormats(ajv)
ajv.addSchema(read('rfcs/rfc7517.json'), `${BASE}rfcs/rfc7517.json`)
ajv.addSchema(read('1960201_json_schema.json'), `${BASE}1960201_json_schema.json`)
const schemaValidate = ajv.getSchema(`${BASE}1960201_json_schema.json`)

const schemaAccepts = (document: unknown) => {
  if (!schemaValidate) throw new Error('JSON schema did not compile')
  return schemaValidate(document) === true
}

const ecList = (jwt: string) => decodeJwt<Record<string, unknown>, LoTEDocument>(jwt).payload

const minimal = (): LoTEDocument => ({
  LoTE: {
    ListAndSchemeInformation: {
      LoTEVersionIdentifier: 1,
      LoTESequenceNumber: 1,
      SchemeOperatorName: [{ lang: 'en', value: 'Operator' }],
      ListIssueDateTime: '2026-10-01T00:00:00Z',
      NextUpdate: '2027-04-01T00:00:00Z',
    },
  },
})

const entity = (overrides: { identity?: unknown; country?: string; supplyPoint?: Record<string, string> } = {}) => ({
  TrustedEntityInformation: {
    TEName: [{ lang: 'en', value: 'Entity' }],
    TEAddress: {
      TEPostalAddress: [{ lang: 'en', StreetAddress: '1 Street', Country: overrides.country ?? 'DE' }],
      TEElectronicAddress: [{ lang: 'en', uriValue: 'mailto:entity@example.com' }],
    },
    TEInformationURI: [{ lang: 'en', uriValue: 'https://example.com/entity' }],
  },
  TrustedEntityServices: [
    {
      ServiceInformation: {
        ServiceName: [{ lang: 'en', value: 'Service' }],
        ServiceDigitalIdentity: overrides.identity ?? {
          X509Certificates: [{ encoding: 'urn:ietf:params:tls-cert-type:x509', specRef: 'RFC5280', val: 'AAAA' }],
        },
        ...(overrides.supplyPoint ? { ServiceSupplyPoints: [overrides.supplyPoint] } : {}),
      },
    },
  ],
})

const withEntities = (...entities: unknown[]) => ({ LoTE: { ...minimal().LoTE, TrustedEntitiesList: entities } })

const withInfo = (info: Record<string, unknown>) => ({
  LoTE: { ListAndSchemeInformation: { ...minimal().LoTE.ListAndSchemeInformation, ...info } },
})

const policy = { LoTEPolicy: { lang: 'en', uriValue: 'https://example.com/policy' } }

const bothAccept: Array<[string, unknown]> = [
  ['the EC PID providers list', ecList(EUPIDProvidersJWT)],
  ['the EC wallet providers list', ecList(WalletProvidersJWT)],
  ['the EC WRPAC providers list', ecList(WRPACProvidersJWT)],
  ['the Launchpad 2026 PID list without entities', ecList(LP26PIDProvidersEmptyJWT)],
  ['the Launchpad 2026 WRPRC list with a string legal notice', ecList(LP26WRPRCProvidersEmptyJWT)],
  ['a list without TrustedEntitiesList', minimal()],
  ['an entity with a minimal address and a certificate', withEntities(entity())],
  [
    'date-times with an offset',
    withInfo({ ListIssueDateTime: '2026-10-23T10:47:49+02:00', NextUpdate: '2027-04-23T10:47:49-05:30' }),
  ],
  [
    'date-times with a lowercase t and z, and a leap second',
    withInfo({ ListIssueDateTime: '2026-10-23t10:47:49z', NextUpdate: '2016-12-31T23:59:60Z' }),
  ],
  [
    'legal notices as strings, the empty string included',
    withInfo({ PolicyOrLegalNotice: [{ LoTELegalNotice: 'Notice' }, { LoTELegalNotice: '' }] }),
  ],
  ['policies only', withInfo({ PolicyOrLegalNotice: [policy, policy] })],
  [
    'a policy next to an item with both keys',
    withInfo({ PolicyOrLegalNotice: [policy, { ...policy, LoTELegalNotice: 'Notice' }] }),
  ],
  ['empty lang and value', withInfo({ SchemeOperatorName: [{ lang: '', value: '' }] })],
  ['a country that is not a 2-letter code', withEntities(entity({ country: 'Germany' }))],
  ['an empty ServiceDigitalIdentity', withEntities(entity({ identity: {} }))],
  [
    'another certificate encoding and specRef, and an empty val',
    withEntities(
      entity({ identity: { X509Certificates: [{ encoding: 'https://example.com/der', specRef: 'X.509', val: '' }] } })
    ),
  ],
  ['an oct JWK', withEntities(entity({ identity: { PublicKeyValues: [{ kty: 'oct' }] } }))],
  [
    'a supply point without ServiceType',
    withEntities(entity({ supplyPoint: { uriValue: 'https://example.com/issue' } })),
  ],
  [
    'a pointer to another list with an empty MimeType and an empty identity',
    withInfo({
      PointersToOtherLoTE: [
        {
          LoTELocation: 'https://example.com/other.json',
          ServiceDigitalIdentities: [{}],
          LoTEQualifiers: [
            { LoTEType: 'https://example.com/type', SchemeOperatorName: [{ lang: 'en', value: 'Op' }], MimeType: '' },
          ],
        },
      ],
    }),
  ],
]

const INFO = 'LoTE.ListAndSchemeInformation'
const SERVICE = 'LoTE.TrustedEntitiesList.0.TrustedEntityServices.0.ServiceInformation'

// Each case names the path validateLoTE reports; the schema must fail at that path or below it
const bothReject: Array<[string, unknown, string]> = [
  ['no ListIssueDateTime', withInfo({ ListIssueDateTime: undefined }), `${INFO}.ListIssueDateTime`],
  [
    'a date-time without a time zone',
    withInfo({ ListIssueDateTime: '2026-10-23T10:47:49' }),
    `${INFO}.ListIssueDateTime`,
  ],
  [
    'a LoTEVersionIdentifier that is not an integer',
    withInfo({ LoTEVersionIdentifier: 1.5 }),
    `${INFO}.LoTEVersionIdentifier`,
  ],
  ['an empty PolicyOrLegalNotice', withInfo({ PolicyOrLegalNotice: [] }), `${INFO}.PolicyOrLegalNotice`],
  [
    'a PolicyOrLegalNotice item with neither key',
    withInfo({ PolicyOrLegalNotice: [{}] }),
    `${INFO}.PolicyOrLegalNotice.0`,
  ],
  [
    'PolicyOrLegalNotice items that all have both keys',
    withInfo({ PolicyOrLegalNotice: [{ ...policy, LoTELegalNotice: 'Notice' }] }),
    `${INFO}.PolicyOrLegalNotice`,
  ],
  [
    'policies and legal notices mixed',
    withInfo({ PolicyOrLegalNotice: [policy, { LoTELegalNotice: 'Notice' }] }),
    `${INFO}.PolicyOrLegalNotice.1`,
  ],
  ['a SchemeTerritory of 3 letters', withInfo({ SchemeTerritory: 'EUR' }), `${INFO}.SchemeTerritory`],
  ['an empty SchemeOperatorName', withInfo({ SchemeOperatorName: [] }), `${INFO}.SchemeOperatorName`],
  [
    'a certificate encoding that is not a URI',
    withEntities(entity({ identity: { X509Certificates: [{ encoding: 'not a uri', val: 'AAAA' }] } })),
    `${SERVICE}.ServiceDigitalIdentity.X509Certificates.0.encoding`,
  ],
  [
    'a supply point without uriValue',
    withEntities(entity({ supplyPoint: { ServiceType: 'https://example.com/type' } })),
    `${SERVICE}.ServiceSupplyPoints.0.uriValue`,
  ],
  [
    'a postal address without Country',
    withEntities({
      ...entity(),
      TrustedEntityInformation: {
        ...entity().TrustedEntityInformation,
        TEAddress: {
          ...entity().TrustedEntityInformation.TEAddress,
          TEPostalAddress: [{ lang: 'en', StreetAddress: '1 Street' }],
        },
      },
    }),
    'LoTE.TrustedEntitiesList.0.TrustedEntityInformation.TEAddress.TEPostalAddress.0.Country',
  ],
  [
    'an entity without services',
    withEntities({ ...entity(), TrustedEntityServices: [] }),
    'LoTE.TrustedEntitiesList.0.TrustedEntityServices',
  ],
]

// validateLoTE accepts these, the schema does not: kept on purpose, each for its reason
const looserThanSchema: Array<[string, unknown, string]> = [
  ['an empty TrustedEntitiesList', withEntities(), 'lists written before createLoTE left the key out'],
  [
    'an entity without TEInformationURI',
    withEntities({
      ...entity(),
      TrustedEntityInformation: { ...entity().TrustedEntityInformation, TEInformationURI: undefined },
    }),
    'optional in the XML schema and in the lists seen so far',
  ],
  [
    'a localized legal notice',
    withInfo({ PolicyOrLegalNotice: [{ LoTELegalNotice: { lang: 'en', value: 'Notice' } }] }),
    'the XML schema form, which lists written before this version use',
  ],
  [
    'an empty identity array',
    withEntities(entity({ identity: { X509Certificates: [], OtherIds: ['id'] } })),
    'minItems is checked only on the arrays that had a minimum before (names, services, PolicyOrLegalNotice)',
  ],
  [
    'an empty DistributionPoints',
    withInfo({ DistributionPoints: [] }),
    'minItems is checked only on the arrays that had a minimum before (names, services, PolicyOrLegalNotice)',
  ],
  [
    'an OKP JWK',
    withEntities(entity({ identity: { PublicKeyValues: [{ kty: 'OKP', crv: 'Ed25519', x: 'AAAA' }] } })),
    'the RFC 7517 sub-schema predates OKP (RFC 8037)',
  ],
  [
    'a HistoricalInformationPeriod that is not an integer',
    withInfo({ HistoricalInformationPeriod: 1.5 }),
    'never checked as an integer, left for a later change',
  ],
  [
    'a supply point ServiceType that is not a URI',
    withEntities(entity({ supplyPoint: { ServiceType: 'issuance', uriValue: 'https://example.com/issue' } })),
    'free text in lists written before this version',
  ],
  ['an unknown property', withInfo({ Unknown: true }), 'zod objects strip unknown keys rather than reject them'],
]

// The schema accepts these, validateLoTE does not
const stricterThanSchema: Array<[string, unknown, string]> = [
  [
    'a URI with a port above 65535',
    withInfo({ LoTEType: 'https://example.com:70000/type' }),
    'z.url() parses with the WHATWG URL parser, the ajv uri format is a regex',
  ],
  [
    'a date-time with a space separator',
    withInfo({ ListIssueDateTime: '2026-10-23 10:47:49Z' }),
    'RFC 3339 section 5.6 has a T, the ajv date-time format also takes a space',
  ],
  [
    'a date-time offset without a colon',
    withInfo({ ListIssueDateTime: '2026-10-23T10:47:49+0200' }),
    'RFC 3339 section 5.6 has a colon in the offset',
  ],
  [
    'a LoTESequenceNumber above 2^53 - 1',
    withInfo({ LoTESequenceNumber: 2 ** 53 }),
    'z.number().int() stops at Number.MAX_SAFE_INTEGER',
  ],
]

// The documents go through JSON as a verifier receives them: undefined values drop out
const asJson = (document: unknown) => JSON.parse(JSON.stringify(document))

// Where ajv failed, as a validateLoTE path: a missing property counts at the property
const schemaErrorPaths = () =>
  (schemaValidate?.errors ?? []).map((error) => {
    const missing = error.keyword === 'required' ? `/${error.params.missingProperty}` : ''
    return `${error.instancePath}${missing}`.split('/').filter(Boolean).join('.')
  })

describe('ETSI TS 119 602 v1.1.1 JSON schema drift', () => {
  it.each(bothAccept)('both accept %s', (_, document) => {
    const json = asJson(document)

    expect(schemaAccepts(json)).toBe(true)
    expect(validateLoTE(json)).toEqual({ valid: true, errors: [] })
  })

  it.each(bothReject)('both reject %s', (_, document, path) => {
    const json = asJson(document)

    expect(schemaAccepts(json)).toBe(false)
    expect(schemaErrorPaths().some((p) => p === path || p.startsWith(`${path}.`))).toBe(true)
    expect(validateLoTE(json).errors.map((e) => e.path)).toContain(path)
  })

  it.each(looserThanSchema)('only validateLoTE accepts %s (%s)', (_, document) => {
    const json = asJson(document)

    expect(schemaAccepts(json)).toBe(false)
    expect(validateLoTE(json).valid).toBe(true)
  })

  it.each(stricterThanSchema)('only the schema accepts %s (%s)', (_, document) => {
    const json = asJson(document)

    expect(schemaAccepts(json)).toBe(true)
    expect(validateLoTE(json).valid).toBe(false)
  })
})
