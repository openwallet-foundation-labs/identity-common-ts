import { SchemaMetaException } from './schema-meta-exception'
import type {
  AttestationFormat,
  BuildDcqlFromSchemaMetaOptions,
  BuildDcqlFromSchemaMetaResult,
  DcqlClaim,
  DcqlClaimsPath,
  DcqlClaimsPathComponent,
  DcqlTrustedAuthority,
  ResolvedSchemaReference,
  SchemaMeta,
  SchemaURIMeta,
} from './types'

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

  return 'items' in node || 'prefixItems' in node
}

/**
 * Positional item schemas of a tuple-typed array, either as `prefixItems`
 * (JSON Schema 2020-12) or as the array form of `items` (draft-07 and earlier).
 * An empty array carries no positional constraint and is not treated as a tuple.
 */
function getTupleItemSchemas(node: unknown): unknown[] | undefined {
  if (!isPlainObject(node)) {
    return undefined
  }

  if (Array.isArray(node.prefixItems) && node.prefixItems.length > 0) {
    return node.prefixItems
  }

  if (Array.isArray(node.items) && node.items.length > 0) {
    return node.items
  }

  return undefined
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

/** A claims path pointer MUST be non-empty, so the schema root itself never yields a claim. */
function pushClaim(claims: DcqlClaim[], path: DcqlClaimsPathComponent[]): void {
  if (path.length === 0) {
    return
  }

  claims.push({ path: path as DcqlClaimsPath })
}

/**
 * Collects the claims below an array schema at `path`. Tuple entries are addressed by their
 * non-negative index, uniformly typed elements by the `null` wildcard, and an array of
 * primitives yields the array-valued claim itself.
 *
 * A rest schema alongside tuple entries (`items` next to `prefixItems`, or `additionalItems`)
 * is skipped, because a claims path pointer cannot address every index from a position onwards.
 */
function collectClaimsFromArraySchema(
  node: unknown,
  path: DcqlClaimsPathComponent[],
  claims: DcqlClaim[],
  ancestors: Set<object>
): void {
  const tupleItems = getTupleItemSchemas(node)
  if (tupleItems) {
    for (const [index, itemSchema] of tupleItems.entries()) {
      const itemPath = [...path, index]

      if (isObjectSchema(itemSchema) || isArraySchema(itemSchema)) {
        collectClaimsFromSchema(itemSchema, itemPath, claims, ancestors)
      } else {
        pushClaim(claims, itemPath)
      }
    }

    return
  }

  const items = isPlainObject(node) ? node.items : undefined
  if (items !== undefined && (isObjectSchema(items) || isArraySchema(items))) {
    collectClaimsFromSchema(items, [...path, null], claims, ancestors)
    return
  }

  pushClaim(claims, path)
}

function collectClaimsFromSchema(
  node: unknown,
  path: DcqlClaimsPathComponent[],
  claims: DcqlClaim[],
  ancestors: Set<object>
): void {
  if (!isPlainObject(node)) {
    pushClaim(claims, path)
    return
  }

  // Guards against schemas that reference themselves. The set holds the nodes on the current
  // branch only, so a sub-schema shared between siblings still yields claims at every path it
  // appears under.
  if (ancestors.has(node)) {
    return
  }

  ancestors.add(node)
  collectClaimsFromSchemaNode(node, path, claims, ancestors)
  ancestors.delete(node)
}

function collectClaimsFromSchemaNode(
  node: Record<string, unknown>,
  path: DcqlClaimsPathComponent[],
  claims: DcqlClaim[],
  ancestors: Set<object>
): void {
  const combinatorKeys = ['allOf', 'anyOf', 'oneOf'] as const
  for (const key of combinatorKeys) {
    const variants = node[key]
    if (Array.isArray(variants)) {
      for (const variant of variants) {
        collectClaimsFromSchema(variant, path, claims, ancestors)
      }
    }
  }

  const properties = node.properties
  if (isPlainObject(properties)) {
    for (const [propertyName, propertySchema] of Object.entries(properties)) {
      const propertyPath = [...path, propertyName]

      if (isArraySchema(propertySchema)) {
        collectClaimsFromArraySchema(propertySchema, propertyPath, claims, ancestors)
        continue
      }

      if (isObjectSchema(propertySchema)) {
        collectClaimsFromSchema(propertySchema, propertyPath, claims, ancestors)
        continue
      }

      pushClaim(claims, propertyPath)
    }

    return
  }

  if (isArraySchema(node)) {
    collectClaimsFromArraySchema(node, path, claims, ancestors)
    return
  }

  pushClaim(claims, path)
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
  const valuesByType = new Map<'etsi_tl', string[]>()

  for (const authority of schemaMeta.trustedAuthorities ?? []) {
    if (authority.frameworkType !== 'etsi_tl') {
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
