import { describe, expect, it } from 'vitest'
import { schemaMeta, schemaURI, trustAuthority } from '../builders'
import { buildDcqlFromSchemaMeta, toDcqlCredentialInput, toDcqlTrustedAuthorities } from '../dcql'

const RULEBOOK_INTEGRITY = 'sha256-cJe/IG7DijmXd2FpecyWJVnZ9EuKKprly5auxGm1uIw='
const SCHEMA_INTEGRITY = 'sha256-M8H+reBt9Nr/s8CRicJrthAnk7UdWyTyONW0N8Z/Axw='

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
      .addTrustAuthority(trustAuthority().frameworkType('etsi_tl').value('https://example.com/tl-1').build())
      .addTrustAuthority(trustAuthority().frameworkType('etsi_tl').value('https://example.com/tl-1').build())
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
      .addTrustAuthority(trustAuthority().frameworkType('etsi_tl').value('https://example.com/tl-1').build())
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
