import { hasher } from '@owf/crypto'
import { base64, compareBytes } from '@owf/identity-common'
import { SchemaMetaException } from './schema-meta-exception'
import { mergeTypeMetadata, type TypeMetadata, TypeMetadataSchema } from './type-metadata'
import type { ResolvedSchemaReference, ResolverContent, ResolveSchemaReferencesOptions, SchemaURI } from './types'

const DEFAULT_MAX_EXTENDS_DEPTH = 10

interface FetchOptions {
  resolve: ResolveSchemaReferencesOptions['resolve']
  verifyIntegrity: boolean
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function parseSri(integrity: string): { algorithm: 'sha256'; digest: Uint8Array } {
  const token = integrity.trim().split(/\s+/)[0]
  const separatorIndex = token.indexOf('-')

  if (separatorIndex <= 0 || separatorIndex >= token.length - 1) {
    throw new SchemaMetaException(`integrity invalid format '${integrity}'`)
  }

  const algorithm = token.slice(0, separatorIndex)
  const digestValue = token.slice(separatorIndex + 1)

  if (algorithm !== 'sha256') {
    throw new SchemaMetaException(`integrity unsupported algorithm '${algorithm}'`)
  }

  let digest: Uint8Array
  try {
    digest = base64.decode(digestValue)
  } catch {
    throw new SchemaMetaException(`integrity invalid base64 digest`)
  }

  if (digest.length === 0) {
    throw new SchemaMetaException(`integrity invalid base64 digest`)
  }

  return { algorithm, digest }
}

/**
 * SRI is defined over the bytes as transferred, so a resolver that returns already-parsed
 * content has destroyed the only thing the digest can be checked against.
 */
function verifySriIntegrity(content: ResolverContent, integrity: string): void {
  if (typeof content !== 'string' && !(content instanceof Uint8Array)) {
    throw new SchemaMetaException(
      'integrity cannot be verified over parsed content: return the response body as a string or Uint8Array'
    )
  }

  const { algorithm, digest } = parseSri(integrity)
  const actual = hasher(content instanceof Uint8Array ? (content.buffer as ArrayBuffer) : content, algorithm)

  if (!compareBytes(actual, digest)) {
    throw new SchemaMetaException('integrity mismatch')
  }
}

function parseJsonContent(content: ResolverContent): unknown {
  if (content instanceof Uint8Array) {
    return JSON.parse(new TextDecoder().decode(content)) as unknown
  }

  if (typeof content === 'string') {
    return JSON.parse(content) as unknown
  }

  return content
}

async function fetchDocument(
  uri: string,
  integrity: string | undefined,
  context: string,
  options: FetchOptions
): Promise<unknown> {
  let content: ResolverContent

  try {
    const result = await options.resolve(uri)
    content = result.content
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error)
    throw new SchemaMetaException(`${context} resolve failed: ${message}`)
  }

  if (options.verifyIntegrity && integrity) {
    try {
      verifySriIntegrity(content, integrity)
    } catch (error) {
      if (error instanceof SchemaMetaException) {
        throw new SchemaMetaException(`${context.replace(/\.uri$/, '')}.${error.message}`)
      }

      const message = error instanceof Error ? error.message : String(error)
      throw new SchemaMetaException(`${context}.integrity verification failed: ${message}`)
    }
  }

  try {
    return parseJsonContent(content)
  } catch {
    throw new SchemaMetaException(`${context} is not valid JSON`)
  }
}

function parseTypeMetadata(document: unknown, context: string): TypeMetadata {
  const result = TypeMetadataSchema.safeParse(document)

  if (!result.success) {
    const messages = result.error.issues.map((issue) => `${issue.path.join('.')}: ${issue.message}`).join('; ')
    throw new SchemaMetaException(`${context} is not valid SD-JWT VC Type Metadata: ${messages}`)
  }

  return result.data
}

/**
 * Walk the `extends` chain towards its root and fold the documents back together, so the
 * returned document carries the inherited claims and members.
 */
async function resolveExtendsChain(
  document: TypeMetadata,
  context: string,
  options: FetchOptions & { maxExtendsDepth: number; visited: Set<string> }
): Promise<TypeMetadata> {
  const chain: TypeMetadata[] = [document]
  let current = document
  let depth = 0

  while (current.extends !== undefined) {
    if (depth >= options.maxExtendsDepth) {
      throw new SchemaMetaException(`${context}.extends exceeds the maximum depth of ${options.maxExtendsDepth}`)
    }

    if (options.visited.has(current.extends)) {
      throw new SchemaMetaException(`${context}.extends forms a cycle at '${current.extends}'`)
    }

    options.visited.add(current.extends)

    const extendsContext = `${context}.extends[${depth}]`
    const parentDocument = await fetchDocument(current.extends, current['extends#integrity'], extendsContext, options)

    current = parseTypeMetadata(parentDocument, extendsContext)
    chain.push(current)
    depth += 1
  }

  return chain.reduceRight((parent, child) => mergeTypeMetadata(parent, child))
}

async function resolveTypeMetadataSchema(
  typeMetadata: TypeMetadata,
  context: string,
  options: FetchOptions
): Promise<Record<string, unknown> | undefined> {
  if (isPlainObject(typeMetadata.schema)) {
    return typeMetadata.schema
  }

  if (typeMetadata.schema_uri === undefined) {
    return undefined
  }

  const document = await fetchDocument(
    typeMetadata.schema_uri,
    typeMetadata['schema_uri#integrity'],
    `${context}.schema_uri`,
    options
  )

  return isPlainObject(document) ? document : undefined
}

async function resolveSdJwtReference(
  document: unknown,
  schemaURI: Extract<SchemaURI, { formatIdentifier: 'dc+sd-jwt' }>,
  context: string,
  options: FetchOptions & { maxExtendsDepth: number }
): Promise<{ typeMetadata?: TypeMetadata; parsedSchema?: Record<string, unknown> }> {
  // References that are a plain JSON Schema rather than Type Metadata stay supported.
  if (!isPlainObject(document) || typeof document.vct !== 'string') {
    return { parsedSchema: isPlainObject(document) ? document : undefined }
  }

  const typeMetadata = await resolveExtendsChain(parseTypeMetadata(document, context), context, {
    ...options,
    visited: new Set<string>([schemaURI.uri]),
  })

  if (typeMetadata.vct !== schemaURI.meta.vct) {
    throw new SchemaMetaException(
      `${context}.vct '${typeMetadata.vct}' does not match the catalogue entry vct '${schemaURI.meta.vct}'`
    )
  }

  return { typeMetadata, parsedSchema: await resolveTypeMetadataSchema(typeMetadata, context, options) }
}

export async function resolveSchemaReferences(
  options: ResolveSchemaReferencesOptions
): Promise<ResolvedSchemaReference[]> {
  const {
    schemaMeta,
    selectedFormats,
    resolve,
    verifyIntegrity = true,
    maxExtendsDepth = DEFAULT_MAX_EXTENDS_DEPTH,
  } = options
  const selectedSet = selectedFormats ? new Set(selectedFormats) : undefined
  const fetchOptions: FetchOptions = { resolve, verifyIntegrity }
  const resolved: ResolvedSchemaReference[] = []

  for (const [index, schemaURI] of schemaMeta.schemaURIs.entries()) {
    if (selectedSet && !selectedSet.has(schemaURI.formatIdentifier)) {
      continue
    }

    const context = `schemaURIs[${index}]`
    const rawSchema = await fetchDocument(schemaURI.uri, schemaURI.integrity, `${context}.uri`, fetchOptions)

    const { typeMetadata, parsedSchema } =
      schemaURI.formatIdentifier === 'dc+sd-jwt'
        ? await resolveSdJwtReference(rawSchema, schemaURI, context, { ...fetchOptions, maxExtendsDepth })
        : { typeMetadata: undefined, parsedSchema: isPlainObject(rawSchema) ? rawSchema : undefined }

    resolved.push({
      format: schemaURI.formatIdentifier,
      uri: schemaURI.uri,
      integrity: schemaURI.integrity,
      meta: schemaURI.meta,
      rawSchema,
      typeMetadata,
      parsedSchema,
    })
  }

  return resolved
}
