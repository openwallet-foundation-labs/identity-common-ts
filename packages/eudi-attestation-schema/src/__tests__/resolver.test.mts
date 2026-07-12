import { createHash } from 'node:crypto'
import { describe, expect, it } from 'vitest'
import { schemaMeta, schemaURI } from '../builders'
import { resolveSchemaReferences } from '../resolver'

function withSri(content: string): string {
  const digest = createHash('sha256').update(Buffer.from(content, 'utf8')).digest('base64')
  return `sha256-${digest}`
}

const RULEBOOK_INTEGRITY = 'sha256-cJe/IG7DijmXd2FpecyWJVnZ9EuKKprly5auxGm1uIw='

describe('resolveSchemaReferences', () => {
  it('resolves JSON string schema documents', async () => {
    const content = '{"type":"object","properties":{"given_name":{"type":"string"}}}'
    const meta = schemaMeta()
      .id('https://example.com/attestation/resolver-json-string')
      .version('1.0.0')
      .rulebookURI('https://example.com/rulebook.md')
      .rulebookIntegrity(RULEBOOK_INTEGRITY)
      .attestationLoS('iso_18045_basic')
      .bindingType('key')
      .addSchemaURI(
        schemaURI()
          .format('dc+sd-jwt')
          .uri('https://example.com/sd-jwt.json')
          .integrity(withSri(content))
          .meta({ vct: 'eu.example.1' })
          .build()
      )
      .build()

    const result = await resolveSchemaReferences({
      schemaMeta: meta,
      resolve: async () => ({ content }),
      verifyIntegrity: true,
    })

    expect(result).toHaveLength(1)
    expect(result[0].format).toBe('dc+sd-jwt')
  })

  it('filters by selected formats', async () => {
    const sdJwtContent = '{"$id":"schema-1"}'
    const mdocContent = '{"$id":"schema-2"}'

    const meta = schemaMeta()
      .id('https://example.com/attestation/resolver-filter')
      .version('1.0.0')
      .rulebookURI('https://example.com/rulebook.md')
      .rulebookIntegrity(RULEBOOK_INTEGRITY)
      .attestationLoS('iso_18045_basic')
      .bindingType('key')
      .addSchemaURI(
        schemaURI()
          .format('dc+sd-jwt')
          .uri('https://example.com/sd-jwt.json')
          .integrity(withSri(sdJwtContent))
          .meta({ vct: 'eu.example.1' })
          .build()
      )
      .addSchemaURI(
        schemaURI()
          .format('mso_mdoc')
          .uri('https://example.com/mdoc.json')
          .integrity(withSri(mdocContent))
          .meta({ doctype_value: 'org.iso.18013.5.1.mDL' })
          .build()
      )
      .build()

    const result = await resolveSchemaReferences({
      schemaMeta: meta,
      selectedFormats: ['mso_mdoc'],
      resolve: async (uri) => ({ content: uri.includes('mdoc') ? mdocContent : sdJwtContent }),
      verifyIntegrity: true,
    })

    expect(result).toHaveLength(1)
    expect(result[0].format).toBe('mso_mdoc')
  })

  it('throws with indexed context when resolver fails', async () => {
    const content = '{}'
    const meta = schemaMeta()
      .id('https://example.com/attestation/resolver-failure')
      .version('1.0.0')
      .rulebookURI('https://example.com/rulebook.md')
      .rulebookIntegrity(RULEBOOK_INTEGRITY)
      .attestationLoS('iso_18045_basic')
      .bindingType('key')
      .addSchemaURI(
        schemaURI()
          .format('dc+sd-jwt')
          .uri('https://example.com/sd-jwt.json')
          .integrity(withSri(content))
          .meta({ vct: 'eu.example.1' })
          .build()
      )
      .build()

    await expect(
      resolveSchemaReferences({
        schemaMeta: meta,
        resolve: async () => {
          throw new Error('network down')
        },
      })
    ).rejects.toThrow('schemaURIs[0].uri resolve failed: network down')
  })

  it('throws when integrity mismatch happens', async () => {
    const content = '{"type":"object"}'

    const meta = schemaMeta()
      .id('https://example.com/attestation/resolver-integrity-mismatch')
      .version('1.0.0')
      .rulebookURI('https://example.com/rulebook.md')
      .rulebookIntegrity(RULEBOOK_INTEGRITY)
      .attestationLoS('iso_18045_basic')
      .bindingType('key')
      .addSchemaURI(
        schemaURI()
          .format('dc+sd-jwt')
          .uri('https://example.com/sd-jwt.json')
          .integrity(withSri('{"different":true}'))
          .meta({ vct: 'eu.example.1' })
          .build()
      )
      .build()

    await expect(
      resolveSchemaReferences({
        schemaMeta: meta,
        verifyIntegrity: true,
        resolve: async () => ({ content }),
      })
    ).rejects.toThrow('schemaURIs[0].integrity mismatch')
  })
})
