import { describe, expect, it } from 'vitest'
import { schemaMeta, schemaURI, trustAuthority } from '../builders'
import { buildDcqlFromSchemaMeta, toDcqlCredentialInput, toDcqlTrustedAuthorities } from '../dcql'

describe('toDcqlTrustedAuthorities', () => {
  it('groups and deduplicates supported trusted authority types', () => {
    const meta = schemaMeta()
      .version('1.0.0')
      .rulebookURI('https://example.com/rulebook.md')
      .attestationLoS('iso_18045_basic')
      .bindingType('key')
      .addSchemaURI(
        schemaURI().format('dc+sd-jwt').uri('https://example.com/sd-jwt.json').meta({ vct: 'eu.example.1' }).build()
      )
      .addTrustAuthority(trustAuthority().frameworkType('aki').value('aki-1').build())
      .addTrustAuthority(trustAuthority().frameworkType('aki').value('aki-1').build())
      .addTrustAuthority(
        trustAuthority().frameworkType('etsi_tl').value('https://example.com/tl-1').isLoTE(true).build()
      )
      .addTrustAuthority(trustAuthority().frameworkType('openid_federation').value('https://example.com/of').build())
      .build()

    const trustedAuthorities = toDcqlTrustedAuthorities(meta)

    expect(trustedAuthorities).toEqual([
      { type: 'aki', values: ['aki-1'] },
      { type: 'etsi_tl', values: ['https://example.com/tl-1'] },
    ])
  })
})

describe('toDcqlCredentialInput', () => {
  it('maps dc+sd-jwt with vct_values', () => {
    const meta = schemaMeta()
      .id('https://example.com/attestation/pid')
      .version('1.0.0')
      .rulebookURI('https://example.com/rulebook.md')
      .attestationLoS('iso_18045_basic')
      .bindingType('key')
      .addSchemaURI(
        schemaURI().format('dc+sd-jwt').uri('https://example.com/pid.json').meta({ vct: 'eu.example.pid.1' }).build()
      )
      .build()

    const credential = toDcqlCredentialInput({
      schemaMeta: meta,
      format: 'dc+sd-jwt',
      index: 0,
    })

    expect(credential).toEqual({
      id: 'credential-1',
      format: 'dc+sd-jwt',
      meta: {
        vct_values: ['eu.example.pid.1'],
      },
    })
  })

  it('maps mso_mdoc with doctype_value', () => {
    const meta = schemaMeta()
      .version('1.0.0')
      .rulebookURI('https://example.com/rulebook.md')
      .attestationLoS('iso_18045_basic')
      .bindingType('key')
      .addSchemaURI(
        schemaURI()
          .format('mso_mdoc')
          .uri('https://example.com/mdl.json')
          .meta({ doctype_value: 'org.iso.18013.5.1.mDL' })
          .build()
      )
      .build()

    const credential = toDcqlCredentialInput({
      schemaMeta: meta,
      format: 'mso_mdoc',
      index: 0,
    })

    expect(credential).toEqual({
      id: 'credential-1',
      format: 'mso_mdoc',
      meta: {
        doctype_value: 'org.iso.18013.5.1.mDL',
      },
    })
  })

  it('throws when mso_mdoc mapping is missing doctype_value', () => {
    const meta = schemaMeta()
      .version('1.0.0')
      .rulebookURI('https://example.com/rulebook.md')
      .attestationLoS('iso_18045_basic')
      .bindingType('key')
      .addSchemaURI(
        schemaURI().format('dc+sd-jwt').uri('https://example.com/pid.json').meta({ vct: 'eu.example.pid.1' }).build()
      )
      .build()

    expect(() =>
      toDcqlCredentialInput({
        schemaMeta: meta,
        format: 'mso_mdoc',
        index: 0,
      })
    ).toThrow("DCQL mapping failed for format 'mso_mdoc': missing doctype_value")
  })

  it('creates deterministic ids with custom prefix', () => {
    const meta = schemaMeta()
      .id('https://example.com/attestation/pid')
      .version('1.0.0')
      .rulebookURI('https://example.com/rulebook.md')
      .attestationLoS('iso_18045_basic')
      .bindingType('key')
      .addSchemaURI(
        schemaURI().format('dc+sd-jwt').uri('https://example.com/pid.json').meta({ vct: 'eu.example.pid.1' }).build()
      )
      .build()

    const credential = toDcqlCredentialInput({
      schemaMeta: meta,
      format: 'dc+sd-jwt',
      index: 2,
      idPrefix: 'input-descriptor',
    })

    expect(credential.id).toBe('input-descriptor-3')
  })

  it('adds claims from resolved JSON schema properties', () => {
    const meta = schemaMeta()
      .id('https://example.com/attestation/pid')
      .version('1.0.0')
      .rulebookURI('https://example.com/rulebook.md')
      .attestationLoS('iso_18045_basic')
      .bindingType('key')
      .addSchemaURI(
        schemaURI().format('dc+sd-jwt').uri('https://example.com/pid.json').meta({ vct: 'eu.example.pid.1' }).build()
      )
      .build()

    const credential = toDcqlCredentialInput({
      schemaMeta: meta,
      format: 'dc+sd-jwt',
      index: 0,
      schemaRef: {
        format: 'dc+sd-jwt',
        uri: 'https://example.com/pid.json',
        meta: { vct: 'eu.example.pid.1' },
        rawSchema: {},
        parsedSchema: {
          type: 'object',
          properties: {
            given_name: { type: 'string' },
            family_name: { type: 'string' },
            address: {
              type: 'object',
              properties: {
                street: { type: 'string' },
                country: { type: 'string' },
              },
            },
            nationalities: {
              type: 'array',
              items: { type: 'string' },
            },
          },
        },
      },
    })

    expect(credential).toEqual({
      id: 'credential-1',
      format: 'dc+sd-jwt',
      meta: {
        vct_values: ['eu.example.pid.1'],
      },
      claims: [
        { path: ['given_name'] },
        { path: ['family_name'] },
        { path: ['address', 'street'] },
        { path: ['address', 'country'] },
        { path: ['nationalities'] },
      ],
    })
  })
})

describe('buildDcqlFromSchemaMeta', () => {
  it('uses first-unused reference for duplicate selected formats', () => {
    const meta = schemaMeta()
      .version('1.0.0')
      .rulebookURI('https://example.com/rulebook.md')
      .attestationLoS('iso_18045_basic')
      .bindingType('key')
      .addSchemaURI(
        schemaURI().format('dc+sd-jwt').uri('https://example.com/pid-1.json').meta({ vct: 'eu.example.pid.1' }).build()
      )
      .addSchemaURI(
        schemaURI().format('dc+sd-jwt').uri('https://example.com/pid-2.json').meta({ vct: 'eu.example.pid.2' }).build()
      )
      .build()

    const result = buildDcqlFromSchemaMeta({
      schemaMeta: meta,
      selectedFormats: ['dc+sd-jwt', 'dc+sd-jwt'],
      resolvedReferences: [
        {
          format: 'dc+sd-jwt',
          uri: 'https://example.com/pid-1.json',
          meta: { vct: 'eu.example.pid.1' },
          rawSchema: {},
          parsedSchema: {},
        },
        {
          format: 'dc+sd-jwt',
          uri: 'https://example.com/pid-2.json',
          meta: { vct: 'eu.example.pid.2' },
          rawSchema: {},
          parsedSchema: {},
        },
      ],
    })

    expect(result.credentials).toEqual([
      {
        id: 'credential-1',
        format: 'dc+sd-jwt',
        meta: { vct_values: ['eu.example.pid.1'] },
      },
      {
        id: 'credential-2',
        format: 'dc+sd-jwt',
        meta: { vct_values: ['eu.example.pid.2'] },
      },
    ])
  })

  it('attaches trusted authorities when enabled', () => {
    const meta = schemaMeta()
      .version('1.0.0')
      .rulebookURI('https://example.com/rulebook.md')
      .attestationLoS('iso_18045_basic')
      .bindingType('key')
      .addSchemaURI(
        schemaURI().format('dc+sd-jwt').uri('https://example.com/pid.json').meta({ vct: 'eu.example.pid.1' }).build()
      )
      .addTrustAuthority(trustAuthority().frameworkType('aki').value('aki-1').build())
      .build()

    const result = buildDcqlFromSchemaMeta({
      schemaMeta: meta,
      selectedFormats: ['dc+sd-jwt'],
      includeTrustedAuthorities: true,
    })

    expect(result.credentials).toEqual([
      {
        id: 'credential-1',
        format: 'dc+sd-jwt',
        meta: { vct_values: ['eu.example.pid.1'] },
        trusted_authorities: [{ type: 'aki', values: ['aki-1'] }],
      },
    ])
  })
})
