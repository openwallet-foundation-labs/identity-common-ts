import { describe, expect, it } from 'vitest'
import { schemaMeta, schemaURI, trustAuthority } from '../builders'

const RULEBOOK_INTEGRITY = 'sha256-cJe/IG7DijmXd2FpecyWJVnZ9EuKKprly5auxGm1uIw='
const SCHEMA_INTEGRITY = 'sha256-M8H+reBt9Nr/s8CRicJrthAnk7UdWyTyONW0N8Z/Axw='

describe('TrustAuthorityBuilder', () => {
  it('should create a trust authority with etsi_tl framework', () => {
    const ta = trustAuthority().frameworkType('etsi_tl').value('https://example.com/trust-list.jws').build()

    expect(ta.frameworkType).toBe('etsi_tl')
    expect(ta.value).toBe('https://example.com/trust-list.jws')
  })

  it('should throw when frameworkType is missing', () => {
    expect(() => {
      trustAuthority().value('https://example.com').build()
    }).toThrow('Invalid TrustAuthority')
  })

  it('should throw when value is missing', () => {
    expect(() => {
      trustAuthority().frameworkType('etsi_tl').build()
    }).toThrow('Invalid TrustAuthority')
  })
})

describe('SchemaURIBuilder', () => {
  it('should create a schema URI for dc+sd-jwt format with vct', () => {
    const schema = schemaURI()
      .format('dc+sd-jwt')
      .uri('https://example.com/schema.json')
      .integrity(SCHEMA_INTEGRITY)
      .meta({ vct: 'eu.europa.ec.eudi.pid.1' })
      .build()

    expect(schema.formatIdentifier).toBe('dc+sd-jwt')
    expect(schema.uri).toBe('https://example.com/schema.json')
    expect(schema.integrity).toBe(SCHEMA_INTEGRITY)
    expect(schema.meta).toEqual({ vct: 'eu.europa.ec.eudi.pid.1' })
  })

  it('should create a schema URI for mso_mdoc format', () => {
    const schema = schemaURI()
      .format('mso_mdoc')
      .uri('https://example.com/schema.json')
      .integrity(SCHEMA_INTEGRITY)
      .meta({ doctype_value: 'org.iso.18013.5.1.mDL' })
      .build()

    expect(schema.formatIdentifier).toBe('mso_mdoc')
    expect(schema.meta).toEqual({ doctype_value: 'org.iso.18013.5.1.mDL' })
  })

  it('should throw when integrity is missing', () => {
    expect(() => {
      schemaURI().format('dc+sd-jwt').uri('https://example.com/schema.json').meta({ vct: 'example.1' }).build()
    }).toThrow('Invalid SchemaURI')
  })

  it('should throw when integrity is not sha256 SRI', () => {
    expect(() => {
      schemaURI()
        .format('dc+sd-jwt')
        .uri('https://example.com/schema.json')
        .integrity('sha512-abc')
        .meta({ vct: 'example.1' })
        .build()
    }).toThrow('Invalid SchemaURI')
  })
})

describe('SchemaMetaBuilder', () => {
  it('should create a minimal SchemaMeta object', () => {
    const meta = schemaMeta()
      .id('https://example.com/attestations/minimal')
      .version('1.0.0')
      .rulebookURI('https://example.com/rulebook.md')
      .rulebookIntegrity(RULEBOOK_INTEGRITY)
      .attestationLoS('iso_18045_basic')
      .bindingType('key')
      .addSchemaURI(
        schemaURI()
          .format('dc+sd-jwt')
          .uri('https://example.com/schema.json')
          .integrity(SCHEMA_INTEGRITY)
          .meta({ vct: 'eu.europa.ec.eudi.pid.1' })
          .build()
      )
      .build()

    expect(meta.version).toBe('1.0.0')
    expect(meta.rulebookURI).toBe('https://example.com/rulebook.md')
    expect(meta.rulebookIntegrity).toBe(RULEBOOK_INTEGRITY)
    expect(meta.attestationLoS).toBe('iso_18045_basic')
    expect(meta.bindingType).toBe('key')
    expect(meta.schemaURIs).toHaveLength(1)
  })

  it('should create a full SchemaMeta with all fields', () => {
    const meta = schemaMeta()
      .id('https://example.com/attestations/membership')
      .version('1.0.0')
      .rulebookURI('https://example.com/rulebook.md')
      .rulebookIntegrity(RULEBOOK_INTEGRITY)
      .addTrustAuthority(trustAuthority().frameworkType('etsi_tl').value('https://example.com/trust-list.jws').build())
      .attestationLoS('iso_18045_basic')
      .bindingType('key')
      .addSchemaURI(
        schemaURI()
          .format('dc+sd-jwt')
          .uri('https://example.com/schema.json')
          .integrity(SCHEMA_INTEGRITY)
          .meta({ vct: 'eu.europa.ec.eudi.pid.1' })
          .build()
      )
      .build()

    expect(meta.id).toBe('https://example.com/attestations/membership')
    expect(meta.trustedAuthorities?.[0].frameworkType).toBe('etsi_tl')
  })

  it('should support both schema formats exactly once', () => {
    const meta = schemaMeta()
      .id('https://example.com/attestations/two-formats')
      .version('1.0.0')
      .rulebookURI('https://example.com/rulebook.md')
      .rulebookIntegrity(RULEBOOK_INTEGRITY)
      .attestationLoS('iso_18045_high')
      .bindingType('claim')
      .addSchemaURI(
        schemaURI()
          .format('dc+sd-jwt')
          .uri('https://example.com/schema-sdjwt.json')
          .integrity(SCHEMA_INTEGRITY)
          .meta({ vct: 'eu.example.schema.1' })
          .build()
      )
      .addSchemaURI(
        schemaURI()
          .format('mso_mdoc')
          .uri('https://example.com/schema-mdoc.json')
          .integrity(SCHEMA_INTEGRITY)
          .meta({ doctype_value: 'org.iso.18013.5.1.mDL' })
          .build()
      )
      .build()

    expect(meta.schemaURIs.map((schema) => schema.formatIdentifier)).toEqual(['dc+sd-jwt', 'mso_mdoc'])
  })

  it('should reject duplicate format identifiers across schema URIs', () => {
    expect(() => {
      schemaMeta()
        .id('https://example.com/attestations/duplicate-formats')
        .version('1.0.0')
        .rulebookURI('https://example.com/rulebook.md')
        .rulebookIntegrity(RULEBOOK_INTEGRITY)
        .attestationLoS('iso_18045_basic')
        .bindingType('none')
        .addSchemaURI(
          schemaURI()
            .format('dc+sd-jwt')
            .uri('https://example.com/schema.json')
            .integrity(SCHEMA_INTEGRITY)
            .meta({ vct: 'eu.example.1' })
            .build()
        )
        .addSchemaURI(
          schemaURI()
            .format('dc+sd-jwt')
            .uri('https://example.com/schema-v2.json')
            .integrity(SCHEMA_INTEGRITY)
            .meta({ vct: 'eu.example.2' })
            .build()
        )
        .build()
    }).toThrow('Invalid SchemaMeta')
  })

  it('should throw when rulebookIntegrity is missing', () => {
    expect(() => {
      schemaMeta()
        .id('https://example.com/attestations/no-rulebook-integrity')
        .version('1.0.0')
        .rulebookURI('https://example.com/rulebook.md')
        .attestationLoS('iso_18045_basic')
        .bindingType('key')
        .addSchemaURI(
          schemaURI()
            .format('dc+sd-jwt')
            .uri('https://example.com/schema.json')
            .integrity(SCHEMA_INTEGRITY)
            .meta({ vct: 'eu.example.1' })
            .build()
        )
        .build()
    }).toThrow('Invalid SchemaMeta')
  })

  it('should throw when id is not a URL', () => {
    expect(() => {
      schemaMeta()
        .id('not-a-url')
        .version('1.0.0')
        .rulebookURI('https://example.com/rulebook.md')
        .rulebookIntegrity(RULEBOOK_INTEGRITY)
        .attestationLoS('iso_18045_basic')
        .bindingType('key')
        .addSchemaURI(
          schemaURI()
            .format('dc+sd-jwt')
            .uri('https://example.com/schema.json')
            .integrity(SCHEMA_INTEGRITY)
            .meta({ vct: 'eu.example.1' })
            .build()
        )
        .build()
    }).toThrow('Invalid SchemaMeta')
  })
})
