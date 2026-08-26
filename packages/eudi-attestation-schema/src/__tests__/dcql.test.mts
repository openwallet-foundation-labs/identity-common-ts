import { describe, expect, it } from 'vitest'
import { schemaMeta, schemaURI, trustAuthority } from '../builders'
import { buildDcqlFromSchemaMeta, toDcqlCredentialInput, toDcqlTrustedAuthorities } from '../dcql'

const RULEBOOK_INTEGRITY = 'sha256-cJe/IG7DijmXd2FpecyWJVnZ9EuKKprly5auxGm1uIw='
const SCHEMA_INTEGRITY = 'sha256-M8H+reBt9Nr/s8CRicJrthAnk7UdWyTyONW0N8Z/Axw='
const VERIFICATION_METHOD = {
  type: 'X509Certificate' as const,
  x509Certificate: 'MIIBczCCARmgAwIBAgIUZt2jkmAgIIiw/wpvJU/4yL7ek/YwCgYIKoZIzj0EAwIw',
}

describe('toDcqlTrustedAuthorities', () => {
  it('groups and deduplicates etsi_tl trusted authorities', () => {
    const meta = schemaMeta()
      .id('https://example.com/attestation/trusted-authorities')
      .version('1.0.0')
      .rulebookURI('https://example.com/rulebook.md')
      .rulebookIntegrity(RULEBOOK_INTEGRITY)
      .attestationLoS('iso_18045_basic')
      .bindingType('key')
      .addSchemaURI(
        schemaURI()
          .format('dc+sd-jwt')
          .uri('https://example.com/sd-jwt.json')
          .integrity(SCHEMA_INTEGRITY)
          .meta({ vct: 'eu.example.1' })
          .build()
      )
      .addTrustAuthority(
        trustAuthority()
          .frameworkType('etsi_tl')
          .value('https://example.com/tl-1')
          .verificationMethod(VERIFICATION_METHOD)
          .build()
      )
      .addTrustAuthority(
        trustAuthority()
          .frameworkType('etsi_tl')
          .value('https://example.com/tl-1')
          .verificationMethod(VERIFICATION_METHOD)
          .build()
      )
      .build()

    const trustedAuthorities = toDcqlTrustedAuthorities(meta)

    expect(trustedAuthorities).toEqual([{ type: 'etsi_tl', values: ['https://example.com/tl-1'] }])
  })
})

describe('toDcqlCredentialInput', () => {
  it('maps dc+sd-jwt with vct_values', () => {
    const meta = schemaMeta()
      .id('https://example.com/attestation/pid')
      .version('1.0.0')
      .rulebookURI('https://example.com/rulebook.md')
      .rulebookIntegrity(RULEBOOK_INTEGRITY)
      .attestationLoS('iso_18045_basic')
      .bindingType('key')
      .addSchemaURI(
        schemaURI()
          .format('dc+sd-jwt')
          .uri('https://example.com/pid.json')
          .integrity(SCHEMA_INTEGRITY)
          .meta({ vct: 'eu.example.pid.1' })
          .build()
      )
      .build()

    const credential = toDcqlCredentialInput({ schemaMeta: meta, format: 'dc+sd-jwt', index: 0 })

    expect(credential).toEqual({
      id: 'credential-1',
      format: 'dc+sd-jwt',
      meta: { vct_values: ['eu.example.pid.1'] },
    })
  })

  it('maps mso_mdoc with doctype_value', () => {
    const meta = schemaMeta()
      .id('https://example.com/attestation/mdoc')
      .version('1.0.0')
      .rulebookURI('https://example.com/rulebook.md')
      .rulebookIntegrity(RULEBOOK_INTEGRITY)
      .attestationLoS('iso_18045_basic')
      .bindingType('key')
      .addSchemaURI(
        schemaURI()
          .format('mso_mdoc')
          .uri('https://example.com/mdl.json')
          .integrity(SCHEMA_INTEGRITY)
          .meta({ doctype_value: 'org.iso.18013.5.1.mDL' })
          .build()
      )
      .build()

    const credential = toDcqlCredentialInput({ schemaMeta: meta, format: 'mso_mdoc', index: 0 })

    expect(credential).toEqual({
      id: 'credential-1',
      format: 'mso_mdoc',
      meta: { doctype_value: 'org.iso.18013.5.1.mDL' },
    })
  })
})

describe('claims path pointers', () => {
  const metaFor = (parsedSchema: Record<string, unknown>) => ({
    schemaMeta: schemaMeta()
      .id('https://example.com/attestation/claims')
      .version('1.0.0')
      .rulebookURI('https://example.com/rulebook.md')
      .rulebookIntegrity(RULEBOOK_INTEGRITY)
      .attestationLoS('iso_18045_basic')
      .bindingType('key')
      .addSchemaURI(
        schemaURI()
          .format('dc+sd-jwt')
          .uri('https://example.com/claims.json')
          .integrity(SCHEMA_INTEGRITY)
          .meta({ vct: 'eu.example.claims.1' })
          .build()
      )
      .build(),
    format: 'dc+sd-jwt' as const,
    index: 0,
    schemaRef: {
      format: 'dc+sd-jwt' as const,
      uri: 'https://example.com/claims.json',
      integrity: SCHEMA_INTEGRITY,
      rawSchema: parsedSchema,
      parsedSchema,
    },
  })

  it('addresses tuple entries with non-negative integers', () => {
    const credential = toDcqlCredentialInput(
      metaFor({
        type: 'object',
        properties: {
          coordinates: {
            type: 'array',
            prefixItems: [{ type: 'number' }, { type: 'number' }],
          },
          legacy_tuple: {
            type: 'array',
            items: [{ type: 'string' }, { type: 'object', properties: { code: { type: 'string' } } }],
          },
        },
      })
    )

    expect(credential.claims).toEqual([
      { path: ['coordinates', 0] },
      { path: ['coordinates', 1] },
      { path: ['legacy_tuple', 0] },
      { path: ['legacy_tuple', 1, 'code'] },
    ])
  })

  it('addresses uniformly typed array elements with the null wildcard', () => {
    const credential = toDcqlCredentialInput(
      metaFor({
        type: 'object',
        properties: {
          nationalities: { type: 'array', items: { type: 'string' } },
          places_of_work: {
            type: 'array',
            items: { type: 'object', properties: { city: { type: 'string' } } },
          },
        },
      })
    )

    expect(credential.claims).toEqual([{ path: ['nationalities'] }, { path: ['places_of_work', null, 'city'] }])
  })

  it('skips a rest schema that positional indices cannot address', () => {
    const credential = toDcqlCredentialInput(
      metaFor({
        type: 'object',
        properties: {
          measurements: { type: 'array', prefixItems: [{ type: 'number' }], items: { type: 'number' } },
          legacy_measurements: {
            type: 'array',
            items: [{ type: 'number' }],
            additionalItems: { type: 'number' },
          },
        },
      })
    )

    expect(credential.claims).toEqual([{ path: ['measurements', 0] }, { path: ['legacy_measurements', 0] }])
  })

  it('treats an empty positional item list as a plain array claim', () => {
    const credential = toDcqlCredentialInput(
      metaFor({
        type: 'object',
        properties: {
          unconstrained: { type: 'array', items: [] },
          unconstrained_prefix: { type: 'array', prefixItems: [] },
        },
      })
    )

    expect(credential.claims).toEqual([{ path: ['unconstrained'] }, { path: ['unconstrained_prefix'] }])
  })

  it('emits claims for a sub-schema shared between sibling properties', () => {
    const address = { type: 'object', properties: { city: { type: 'string' } } }

    const credential = toDcqlCredentialInput(
      metaFor({ type: 'object', properties: { home_address: address, work_address: address } })
    )

    expect(credential.claims).toEqual([{ path: ['home_address', 'city'] }, { path: ['work_address', 'city'] }])
  })

  it('terminates on a self-referencing schema without emitting an empty path', () => {
    const node: Record<string, unknown> = { type: 'object' }
    node.properties = { self: node, name: { type: 'string' } }

    const credential = toDcqlCredentialInput(metaFor(node))

    expect(credential.claims).toEqual([{ path: ['name'] }])
  })
})

describe('buildDcqlFromSchemaMeta', () => {
  it('creates credentials for selected formats', () => {
    const meta = schemaMeta()
      .id('https://example.com/attestation/dcql-selected-formats')
      .version('1.0.0')
      .rulebookURI('https://example.com/rulebook.md')
      .rulebookIntegrity(RULEBOOK_INTEGRITY)
      .attestationLoS('iso_18045_basic')
      .bindingType('key')
      .addSchemaURI(
        schemaURI()
          .format('dc+sd-jwt')
          .uri('https://example.com/pid.json')
          .integrity(SCHEMA_INTEGRITY)
          .meta({ vct: 'eu.example.pid.1' })
          .build()
      )
      .addSchemaURI(
        schemaURI()
          .format('mso_mdoc')
          .uri('https://example.com/mdl.json')
          .integrity(SCHEMA_INTEGRITY)
          .meta({ doctype_value: 'org.iso.18013.5.1.mDL' })
          .build()
      )
      .addTrustAuthority(
        trustAuthority()
          .frameworkType('etsi_tl')
          .value('https://example.com/tl-1')
          .verificationMethod(VERIFICATION_METHOD)
          .build()
      )
      .build()

    const result = buildDcqlFromSchemaMeta({
      schemaMeta: meta,
      selectedFormats: ['dc+sd-jwt', 'mso_mdoc'],
      includeTrustedAuthorities: true,
    })

    expect(result.credentials).toEqual([
      {
        id: 'credential-1',
        format: 'dc+sd-jwt',
        meta: { vct_values: ['eu.example.pid.1'] },
        trusted_authorities: [{ type: 'etsi_tl', values: ['https://example.com/tl-1'] }],
      },
      {
        id: 'credential-2',
        format: 'mso_mdoc',
        meta: { doctype_value: 'org.iso.18013.5.1.mDL' },
        trusted_authorities: [{ type: 'etsi_tl', values: ['https://example.com/tl-1'] }],
      },
    ])
  })
})
