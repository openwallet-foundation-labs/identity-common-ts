import { createHash } from 'node:crypto'
import { describe, expect, it } from 'vitest'
import { schemaMeta, schemaURI } from '../builders'
import { resolveSchemaReferences } from '../resolver'

function withSri(content: string, algorithm: 'sha256' | 'sha384' | 'sha512' = 'sha256'): string {
  const digest = createHash(algorithm).update(Buffer.from(content, 'utf8')).digest('base64')
  return `${algorithm}-${digest}`
}

describe('resolveSchemaReferences', () => {
  it('resolves JSON string schema documents', async () => {
    const content = '{"type":"object","properties":{"given_name":{"type":"string"}}}'
    const meta = schemaMeta()
      .version('1.0.0')
      .rulebookURI('https://example.com/rulebook.md')
      .attestationLoS('iso_18045_basic')
      .bindingType('key')
      .addSchemaURI(
        schemaURI().format('dc+sd-jwt').uri('https://example.com/sd-jwt.json').meta({ vct: 'eu.example.1' }).build()
      )
      .build()

    const result = await resolveSchemaReferences({
      schemaMeta: meta,
      resolve: async () => ({ content }),
    })

    expect(result).toHaveLength(1)
    expect(result[0].format).toBe('dc+sd-jwt')
    expect(result[0].parsedSchema).toEqual({
      type: 'object',
      properties: {
        given_name: { type: 'string' },
      },
    })
  })

  it('resolves object schema documents and filters by selected formats', async () => {
    const meta = schemaMeta()
      .version('1.0.0')
      .rulebookURI('https://example.com/rulebook.md')
      .attestationLoS('iso_18045_basic')
      .bindingType('key')
      .addSchemaURI(
        schemaURI().format('dc+sd-jwt').uri('https://example.com/sd-jwt.json').meta({ vct: 'eu.example.1' }).build()
      )
      .addSchemaURI(
        schemaURI()
          .format('mso_mdoc')
          .uri('https://example.com/mdoc.json')
          .meta({ doctype_value: 'org.iso.18013.5.1.mDL' })
          .build()
      )
      .build()

    const result = await resolveSchemaReferences({
      schemaMeta: meta,
      selectedFormats: ['mso_mdoc'],
      resolve: async (uri) => ({ content: { uri, ok: true } }),
    })

    expect(result).toHaveLength(1)
    expect(result[0].format).toBe('mso_mdoc')
    expect(result[0].parsedSchema).toEqual({ uri: 'https://example.com/mdoc.json', ok: true })
  })

  it('throws with indexed context when resolver fails', async () => {
    const meta = schemaMeta()
      .version('1.0.0')
      .rulebookURI('https://example.com/rulebook.md')
      .attestationLoS('iso_18045_basic')
      .bindingType('key')
      .addSchemaURI(
        schemaURI().format('dc+sd-jwt').uri('https://example.com/sd-jwt.json').meta({ vct: 'eu.example.1' }).build()
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

  it('verifies integrity for sha256 and sha512', async () => {
    const sdJwtContent = '{"$id":"schema-1"}'
    const mdocContent = '{"$id":"schema-2"}'

    const meta = schemaMeta()
      .version('1.0.0')
      .rulebookURI('https://example.com/rulebook.md')
      .attestationLoS('iso_18045_basic')
      .bindingType('key')
      .addSchemaURI(
        schemaURI()
          .format('dc+sd-jwt')
          .uri('https://example.com/sd-jwt.json')
          .integrity(withSri(sdJwtContent, 'sha256'))
          .meta({ vct: 'eu.example.1' })
          .build()
      )
      .addSchemaURI(
        schemaURI()
          .format('mso_mdoc')
          .uri('https://example.com/mdoc.json')
          .integrity(withSri(mdocContent, 'sha512'))
          .meta({ doctype_value: 'org.iso.18013.5.1.mDL' })
          .build()
      )
      .build()

    const result = await resolveSchemaReferences({
      schemaMeta: meta,
      verifyIntegrity: true,
      resolve: async (uri) => ({
        content: uri.includes('sd-jwt') ? sdJwtContent : mdocContent,
      }),
    })

    expect(result).toHaveLength(2)
  })

  it('throws when integrity mismatch happens', async () => {
    const content = '{"type":"object"}'

    const meta = schemaMeta()
      .version('1.0.0')
      .rulebookURI('https://example.com/rulebook.md')
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

  it('throws when integrity algorithm is unsupported', async () => {
    const meta = schemaMeta()
      .version('1.0.0')
      .rulebookURI('https://example.com/rulebook.md')
      .attestationLoS('iso_18045_basic')
      .bindingType('key')
      .addSchemaURI(
        schemaURI()
          .format('dc+sd-jwt')
          .uri('https://example.com/sd-jwt.json')
          .integrity('md5-aaaa')
          .meta({ vct: 'eu.example.1' })
          .build()
      )
      .build()

    await expect(
      resolveSchemaReferences({
        schemaMeta: meta,
        verifyIntegrity: true,
        resolve: async () => ({ content: '{}' }),
      })
    ).rejects.toThrow("schemaURIs[0].integrity unsupported algorithm 'md5'")
  })
})
