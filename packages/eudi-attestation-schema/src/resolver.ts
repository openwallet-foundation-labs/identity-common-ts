import { hasher } from '@owf/crypto'
import { base64, compareBytes } from '@owf/identity-common'
import { SchemaMetaException } from './schema-meta-exception'
import type { ResolvedSchemaReference, ResolveSchemaReferencesOptions } from './types'

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function parseSri(integrity: string): { algorithm: 'sha256' | 'sha384' | 'sha512'; digest: Uint8Array } {
  const token = integrity.trim().split(/\s+/)[0]
  const separatorIndex = token.indexOf('-')

  if (separatorIndex <= 0 || separatorIndex >= token.length - 1) {
    throw new SchemaMetaException(`integrity invalid format '${integrity}'`)
  }

  const algorithm = token.slice(0, separatorIndex)
  const digestValue = token.slice(separatorIndex + 1)

  if (algorithm !== 'sha256' && algorithm !== 'sha384' && algorithm !== 'sha512') {
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

function verifySriIntegrity(content: string | object, integrity: string): void {
  const { algorithm, digest } = parseSri(integrity)
  const normalized = typeof content === 'string' ? content : JSON.stringify(content)
  const actual = hasher(normalized, algorithm)

  if (!compareBytes(actual, digest)) {
    throw new SchemaMetaException('integrity mismatch')
  }
}

export async function resolveSchemaReferences(
  options: ResolveSchemaReferencesOptions
): Promise<ResolvedSchemaReference[]> {
  const { schemaMeta, selectedFormats, resolve, verifyIntegrity = false } = options
  const selectedSet = selectedFormats ? new Set(selectedFormats) : undefined
  const resolved: ResolvedSchemaReference[] = []

  for (const [index, schemaURI] of schemaMeta.schemaURIs.entries()) {
    if (selectedSet && !selectedSet.has(schemaURI.formatIdentifier)) {
      continue
    }

    let content: string | object

    try {
      const result = await resolve(schemaURI.uri)
      content = result.content
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error)
      throw new SchemaMetaException(`schemaURIs[${index}].uri resolve failed: ${message}`)
    }

    if (verifyIntegrity && schemaURI.integrity) {
      try {
        verifySriIntegrity(content, schemaURI.integrity)
      } catch (error) {
        if (error instanceof SchemaMetaException) {
          throw new SchemaMetaException(`schemaURIs[${index}].${error.message}`)
        }

        const message = error instanceof Error ? error.message : String(error)
        throw new SchemaMetaException(`schemaURIs[${index}].integrity verification failed: ${message}`)
      }
    }

    let rawSchema: unknown
    let parsedSchema: Record<string, unknown> | undefined

    if (typeof content === 'string') {
      try {
        const parsed = JSON.parse(content) as unknown
        rawSchema = parsed
        if (isPlainObject(parsed)) {
          parsedSchema = parsed
        }
      } catch {
        rawSchema = content
      }
    } else {
      rawSchema = content
      if (isPlainObject(content)) {
        parsedSchema = content
      }
    }

    resolved.push({
      format: schemaURI.formatIdentifier,
      uri: schemaURI.uri,
      integrity: schemaURI.integrity,
      meta: schemaURI.meta,
      rawSchema,
      parsedSchema,
    })
  }

  return resolved
}
