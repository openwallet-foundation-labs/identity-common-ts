import { SchemaMetaException } from './schema-meta-exception'
import type {
  AttestationFormat,
  BuildDcqlFromSchemaMetaOptions,
  BuildDcqlFromSchemaMetaResult,
  DcqlTrustedAuthority,
  ResolvedSchemaReference,
  SchemaMeta,
  SchemaURIMeta,
} from './types'

type DcqlClaim = { path: Array<string | null> }

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function getVct(meta: SchemaURIMeta | undefined): string | undefined {
  if (meta && 'vct' in meta && typeof meta.vct === 'string') {
    return meta.vct
  }

  return undefined
}

function getDocTypeValue(meta: SchemaURIMeta | undefined): string | undefined {
  if (meta && 'doctype_value' in meta && typeof meta.doctype_value === 'string') {
    return meta.doctype_value
  }

  return undefined
}

function getFirstSchemaMetaByFormat(schemaMeta: SchemaMeta, format: AttestationFormat): SchemaURIMeta | undefined {
  const entry = schemaMeta.schemaURIs.find((value) => value.formatIdentifier === format)
  return entry?.meta
}

function isArraySchema(node: unknown): boolean {
  if (!isPlainObject(node)) {
    return false
  }

  if (node.type === 'array') {
    return true
  }

  if (Array.isArray(node.type) && node.type.includes('array')) {
    return true
  }

  return 'items' in node
}

function isObjectSchema(node: unknown): boolean {
  if (!isPlainObject(node)) {
    return false
  }

  if (isPlainObject(node.properties)) {
    return true
  }

  if (node.type === 'object') {
    return true
  }

  if (Array.isArray(node.type) && node.type.includes('object')) {
    return true
  }

  return false
}

function collectClaimsFromSchema(
  node: unknown,
  path: Array<string | null>,
  claims: DcqlClaim[],
  seen: Set<object>
): void {
  if (!isPlainObject(node)) {
    if (path.length > 0) {
      claims.push({ path })
    }
    return
  }

  if (seen.has(node)) {
    return
  }
  seen.add(node)

  const combinatorKeys = ['allOf', 'anyOf', 'oneOf'] as const
  for (const key of combinatorKeys) {
    const variants = node[key]
    if (Array.isArray(variants)) {
      for (const variant of variants) {
        collectClaimsFromSchema(variant, path, claims, seen)
      }
    }
  }

  const properties = node.properties
  if (isPlainObject(properties)) {
    const propertyEntries = Object.entries(properties)

    for (const [propertyName, propertySchema] of propertyEntries) {
      const propertyPath = [...path, propertyName]

      if (isArraySchema(propertySchema)) {
        const items = isPlainObject(propertySchema) ? propertySchema.items : undefined
        if (items !== undefined && (isObjectSchema(items) || isArraySchema(items))) {
          collectClaimsFromSchema(items, [...propertyPath, null], claims, seen)
        } else {
          claims.push({ path: propertyPath })
        }
        continue
      }

      if (isObjectSchema(propertySchema)) {
        collectClaimsFromSchema(propertySchema, propertyPath, claims, seen)
        continue
      }

      claims.push({ path: propertyPath })
    }

    return
  }

  const items = node.items
  if (items !== undefined) {
    if (isObjectSchema(items) || isArraySchema(items)) {
      collectClaimsFromSchema(items, [...path, null], claims, seen)
    } else if (path.length > 0) {
      claims.push({ path })
    }
    return
  }

  if (path.length > 0) {
    claims.push({ path })
  }
}

function getClaimsFromSchema(schemaRef?: ResolvedSchemaReference): DcqlClaim[] {
  const schema = schemaRef?.parsedSchema
  if (!schema) {
    return []
  }

  const claims: DcqlClaim[] = []
  collectClaimsFromSchema(schema, [], claims, new Set<object>())

  const deduped = new Map<string, DcqlClaim>()
  for (const claim of claims) {
    const key = JSON.stringify(claim.path)
    if (!deduped.has(key)) {
      deduped.set(key, claim)
    }
  }

  return [...deduped.values()]
}

export function toDcqlTrustedAuthorities(schemaMeta: SchemaMeta): DcqlTrustedAuthority[] {
  const valuesByType = new Map<'aki' | 'etsi_tl', string[]>()

  for (const authority of schemaMeta.trustedAuthorities ?? []) {
    if (authority.frameworkType !== 'aki' && authority.frameworkType !== 'etsi_tl') {
      continue
    }

    const existing = valuesByType.get(authority.frameworkType) ?? []
    if (!existing.includes(authority.value)) {
      existing.push(authority.value)
      valuesByType.set(authority.frameworkType, existing)
    }
  }

  const result: DcqlTrustedAuthority[] = []

  for (const [type, values] of valuesByType.entries()) {
    if (values.length > 0) {
      result.push({ type, values })
    }
  }

  return result
}

export function toDcqlCredentialInput(params: {
  schemaMeta: SchemaMeta
  format: AttestationFormat
  index: number
  schemaRef?: ResolvedSchemaReference
  idPrefix?: string
}): Record<string, unknown> {
  const { schemaMeta, format, index, schemaRef, idPrefix } = params
  const credential: Record<string, unknown> = {
    id: `${idPrefix ?? 'credential'}-${index + 1}`,
    format,
  }
  const claims = getClaimsFromSchema(schemaRef)
  if (claims.length > 0) {
    credential.claims = claims
  }

  if (format === 'dc+sd-jwt') {
    const value = getVct(schemaRef?.meta) ?? getVct(getFirstSchemaMetaByFormat(schemaMeta, format)) ?? schemaMeta.id

    if (!value) {
      throw new SchemaMetaException(`DCQL mapping failed for format '${format}': missing vct value`)
    }

    credential.meta = { vct_values: [value] }
  }

  if (format === 'mso_mdoc') {
    const value = getDocTypeValue(schemaRef?.meta) ?? getDocTypeValue(getFirstSchemaMetaByFormat(schemaMeta, format))

    if (!value) {
      throw new SchemaMetaException(`DCQL mapping failed for format '${format}': missing doctype_value`)
    }

    credential.meta = { doctype_value: value }
  }

  return credential
}

export function buildDcqlFromSchemaMeta(options: BuildDcqlFromSchemaMetaOptions): BuildDcqlFromSchemaMetaResult {
  const { schemaMeta, selectedFormats, resolvedReferences = [], includeTrustedAuthorities = false, idPrefix } = options
  const consumed = new Set<number>()
  const trustedAuthorities = includeTrustedAuthorities ? toDcqlTrustedAuthorities(schemaMeta) : []

  const credentials = selectedFormats.map((format, index) => {
    const referenceIndex = resolvedReferences.findIndex(
      (reference, candidateIndex) => reference.format === format && !consumed.has(candidateIndex)
    )

    const schemaRef = referenceIndex >= 0 ? resolvedReferences[referenceIndex] : undefined
    if (referenceIndex >= 0) {
      consumed.add(referenceIndex)
    }

    const credential = toDcqlCredentialInput({
      schemaMeta,
      format,
      index,
      schemaRef,
      idPrefix,
    })

    if (includeTrustedAuthorities && trustedAuthorities.length > 0) {
      credential.trusted_authorities = trustedAuthorities
    }

    return credential
  })

  return { credentials }
}
