import { createHash } from 'node:crypto'
import { describe, expect, it } from 'vitest'
import { schemaMeta, schemaURI } from '../builders'
import { buildDcqlFromSchemaMeta } from '../dcql'
import { resolveSchemaReferences } from '../resolver'
import { mergeTypeMetadata, TypeMetadataSchema } from '../type-metadata'

const RULEBOOK_INTEGRITY = 'sha256-cJe/IG7DijmXd2FpecyWJVnZ9EuKKprly5auxGm1uIw='
const VCT = 'https://example.com/credentials/education'
const PARENT_VCT = 'https://example.com/credentials/base'

function withSri(content: string): string {
  return `sha256-${createHash('sha256').update(Buffer.from(content, 'utf8')).digest('base64')}`
}

function buildMeta(uri: string, integrity: string, vct = VCT) {
  return schemaMeta()
    .id('https://example.com/attestations/education')
    .version('1.0.0')
    .rulebookURI('https://example.com/rulebook.md')
    .rulebookIntegrity(RULEBOOK_INTEGRITY)
    .attestationLoS('iso_18045_basic')
    .bindingType('key')
    .addSchemaURI(schemaURI().format('dc+sd-jwt').uri(uri).integrity(integrity).meta({ vct }).build())
    .build()
}

function documentServer(documents: Record<string, string>) {
  return async (uri: string) => {
    const content = documents[uri]
    if (content === undefined) {
      throw new Error(`unknown uri ${uri}`)
    }
    return { content }
  }
}

describe('TypeMetadataSchema', () => {
  it('accepts the SD-JWT VC Type Metadata format', () => {
    const result = TypeMetadataSchema.safeParse({
      vct: VCT,
      claims: [{ path: ['given_name'], sd: 'allowed' }],
      display: [{ locale: 'en', name: 'Education Credential' }],
    })

    expect(result.success).toBe(true)
  })

  it('preserves unknown members', () => {
    const result = TypeMetadataSchema.parse({ vct: VCT, 'x-vendor': 'value' })
    expect(result['x-vendor']).toBe('value')
  })
})

describe('mergeTypeMetadata', () => {
  it('lets the extending document win and merges claims per path', () => {
    const merged = mergeTypeMetadata(
      { vct: PARENT_VCT, name: 'Base', claims: [{ path: ['given_name'], sd: 'allowed' }] },
      { vct: VCT, claims: [{ path: ['given_name'], sd: 'always' }, { path: ['degree'] }] }
    )

    expect(merged.vct).toBe(VCT)
    expect(merged.name).toBe('Base')
    expect(merged.claims).toEqual([{ path: ['given_name'], sd: 'always' }, { path: ['degree'] }])
  })
})

describe('resolveSchemaReferences with Type Metadata', () => {
  it('derives claims from Type Metadata rather than the JSON Schema', async () => {
    const typeMetadata = JSON.stringify({
      vct: VCT,
      claims: [
        { path: ['given_name'], sd: 'allowed' },
        { path: ['address', 'country'], sd: 'always' },
        { path: ['degrees', null, 'type'] },
      ],
    })
    const uri = 'https://example.com/type-metadata.json'
    const meta = buildMeta(uri, withSri(typeMetadata))

    const resolvedReferences = await resolveSchemaReferences({
      schemaMeta: meta,
      resolve: documentServer({ [uri]: typeMetadata }),
    })

    expect(resolvedReferences[0].typeMetadata?.vct).toBe(VCT)
    expect(resolvedReferences[0].parsedSchema).toBeUndefined()

    const dcql = buildDcqlFromSchemaMeta({
      schemaMeta: meta,
      selectedFormats: ['dc+sd-jwt'],
      resolvedReferences,
    })

    expect(dcql.credentials[0].claims).toEqual([
      { path: ['given_name'] },
      { path: ['address', 'country'] },
      { path: ['degrees', null, 'type'] },
    ])
  })

  it('follows the extends chain and inherits claims', async () => {
    const parentUri = 'https://example.com/base.json'
    const parent = JSON.stringify({
      vct: PARENT_VCT,
      claims: [{ path: ['given_name'] }],
    })
    const child = JSON.stringify({
      vct: VCT,
      extends: parentUri,
      'extends#integrity': withSri(parent),
      claims: [{ path: ['degree'] }],
    })
    const uri = 'https://example.com/type-metadata.json'

    const resolvedReferences = await resolveSchemaReferences({
      schemaMeta: buildMeta(uri, withSri(child)),
      resolve: documentServer({ [uri]: child, [parentUri]: parent }),
    })

    expect(resolvedReferences[0].typeMetadata?.vct).toBe(VCT)
    expect(resolvedReferences[0].typeMetadata?.claims).toEqual([{ path: ['given_name'] }, { path: ['degree'] }])
    expect(resolvedReferences[0].parsedSchema).toBeUndefined()
  })

  it('detects a cycle in the extends chain', async () => {
    const uri = 'https://example.com/type-metadata.json'
    const otherUri = 'https://example.com/other.json'
    const document = JSON.stringify({ vct: VCT, extends: otherUri })
    const other = JSON.stringify({ vct: PARENT_VCT, extends: otherUri })

    await expect(
      resolveSchemaReferences({
        schemaMeta: buildMeta(uri, withSri(document)),
        resolve: documentServer({ [uri]: document, [otherUri]: other }),
      })
    ).rejects.toThrow(/forms a cycle/)
  })

  it('enforces the extends depth limit', async () => {
    const uri = 'https://example.com/type-metadata.json'
    const documents: Record<string, string> = {}
    const chainUri = (index: number) => `https://example.com/base-${index}.json`

    documents[uri] = JSON.stringify({ vct: VCT, extends: chainUri(0) })
    for (let index = 0; index < 5; index += 1) {
      documents[chainUri(index)] = JSON.stringify({
        vct: `${PARENT_VCT}/${index}`,
        extends: chainUri(index + 1),
      })
    }

    await expect(
      resolveSchemaReferences({
        schemaMeta: buildMeta(uri, withSri(documents[uri])),
        resolve: documentServer(documents),
        maxExtendsDepth: 2,
      })
    ).rejects.toThrow('exceeds the maximum depth of 2')
  })

  it('rejects Type Metadata whose vct does not match the catalogue entry', async () => {
    const typeMetadata = JSON.stringify({ vct: 'https://example.com/credentials/other' })
    const uri = 'https://example.com/type-metadata.json'

    await expect(
      resolveSchemaReferences({
        schemaMeta: buildMeta(uri, withSri(typeMetadata)),
        resolve: documentServer({ [uri]: typeMetadata }),
      })
    ).rejects.toThrow(/does not match the catalogue entry vct/)
  })

  it('still accepts a plain JSON Schema reference', async () => {
    const document = '{"type":"object","properties":{"given_name":{"type":"string"}}}'
    const uri = 'https://example.com/schema.json'

    const resolvedReferences = await resolveSchemaReferences({
      schemaMeta: buildMeta(uri, withSri(document)),
      resolve: documentServer({ [uri]: document }),
    })

    expect(resolvedReferences[0].typeMetadata).toBeUndefined()
    expect(resolvedReferences[0].parsedSchema).toEqual({
      type: 'object',
      properties: { given_name: { type: 'string' } },
    })
  })
})

describe('resolver integrity contract', () => {
  it('verifies integrity by default', async () => {
    const uri = 'https://example.com/schema.json'

    await expect(
      resolveSchemaReferences({
        schemaMeta: buildMeta(uri, withSri('{"expected":true}')),
        resolve: documentServer({ [uri]: '{"actual":true}' }),
      })
    ).rejects.toThrow('schemaURIs[0].integrity mismatch')
  })

  it('accepts Uint8Array content', async () => {
    const document = '{"type":"object"}'
    const uri = 'https://example.com/schema.json'

    const resolvedReferences = await resolveSchemaReferences({
      schemaMeta: buildMeta(uri, withSri(document)),
      resolve: async () => ({ content: new TextEncoder().encode(document) }),
    })

    expect(resolvedReferences[0].parsedSchema).toEqual({ type: 'object' })
  })

  it('refuses to verify integrity over parsed content', async () => {
    const uri = 'https://example.com/schema.json'

    await expect(
      resolveSchemaReferences({
        schemaMeta: buildMeta(uri, withSri('{"type":"object"}')),
        resolve: async () => ({ content: { type: 'object' } }),
      })
    ).rejects.toThrow(/integrity cannot be verified over parsed content/)
  })

  it('allows parsed content when integrity verification is disabled', async () => {
    const uri = 'https://example.com/schema.json'

    const resolvedReferences = await resolveSchemaReferences({
      schemaMeta: buildMeta(uri, withSri('{"type":"object"}')),
      resolve: async () => ({ content: { type: 'object' } }),
      verifyIntegrity: false,
    })

    expect(resolvedReferences[0].parsedSchema).toEqual({ type: 'object' })
  })
})
