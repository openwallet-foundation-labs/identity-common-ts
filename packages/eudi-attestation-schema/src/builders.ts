import { SchemaMetaException } from './schema-meta-exception'
import { SchemaMetaSchema, SchemaURISchema, TrustAuthoritySchema } from './schemas'
import type {
  AttestationFormat,
  AttestationLoS,
  BindingType,
  FrameworkType,
  SchemaMeta,
  SchemaURI,
  SchemaURIMeta,
  TrustAuthority,
} from './types'

/**
 * Builder for creating TrustAuthority objects with a fluent API
 */
export class TrustAuthorityBuilder {
  private data: Partial<TrustAuthority> = {}

  /**
   * Set the trust framework type
   */
  frameworkType(type: FrameworkType): this {
    this.data.frameworkType = type
    return this
  }

  /**
   * Set the trust authority value (URI for etsi_tl)
   */
  value(value: string): this {
    this.data.value = value
    return this
  }

  /**
   * Build the TrustAuthority object
   */
  build(): TrustAuthority {
    const result = TrustAuthoritySchema.safeParse(this.data)

    if (!result.success) {
      const messages = result.error.issues.map((i) => `${i.path.join('.')}: ${i.message}`).join('\n')
      throw new SchemaMetaException(`Invalid TrustAuthority:\n${messages}`)
    }

    return result.data
  }
}

/**
 * Builder for creating SchemaURI objects with a fluent API
 */
export class SchemaURIBuilder {
  private data: Record<string, unknown> = {}

  /**
   * Set the format identifier
   */
  format(format: AttestationFormat): this {
    this.data.formatIdentifier = format
    return this
  }

  /**
   * Set the schema URI
   */
  uri(uri: string): this {
    this.data.uri = uri
    return this
  }

  /**
   * Set required schema integrity metadata (W3C SRI sha256 format, e.g. "sha256-...")
   */
  integrity(integrity: string): this {
    this.data.integrity = integrity
    return this
  }

  /**
   * Set the format-specific credential metadata.
   * - dc+sd-jwt: provide { vct }
   * - mso_mdoc: provide { doctype_value }
   * - other formats: provide {}
   */
  meta(meta: SchemaURIMeta): this {
    this.data.meta = meta
    return this
  }

  /**
   * Build the SchemaURI object
   */
  build(): SchemaURI {
    const result = SchemaURISchema.safeParse(this.data)

    if (!result.success) {
      const messages = result.error.issues.map((i) => `${i.path.join('.')}: ${i.message}`).join('\n')
      throw new SchemaMetaException(`Invalid SchemaURI:\n${messages}`)
    }

    return result.data
  }
}

/**
 * Builder for creating SchemaMeta objects with a fluent API
 */
export class SchemaMetaBuilder {
  private data: Partial<SchemaMeta> = {}

  /**
   * Set the schema identifier
   */
  id(id: string): this {
    this.data.id = id
    return this
  }

  /**
   * Set the schema version (SemVer)
   */
  version(version: string): this {
    this.data.version = version
    return this
  }

  /**
   * Set the Attestation Rulebook URI
   */
  rulebookURI(uri: string): this {
    this.data.rulebookURI = uri
    return this
  }

  /**
   * Set required integrity metadata for the Attestation Rulebook (W3C SRI sha256 format)
   */
  rulebookIntegrity(integrity: string): this {
    this.data.rulebookIntegrity = integrity
    return this
  }

  /**
   * Add a trusted authority
   */
  addTrustAuthority(trustAuthority: TrustAuthority): this {
    this.data.trustedAuthorities = this.data.trustedAuthorities ?? []
    this.data.trustedAuthorities.push(trustAuthority)
    return this
  }

  /**
   * Set the level of security
   */
  attestationLoS(los: AttestationLoS): this {
    this.data.attestationLoS = los
    return this
  }

  /**
   * Set the cryptographic binding type
   */
  bindingType(type: BindingType): this {
    this.data.bindingType = type
    return this
  }

  /**
   * Add a schema URI
   */
  addSchemaURI(schemaURI: SchemaURI): this {
    this.data.schemaURIs = this.data.schemaURIs ?? []
    this.data.schemaURIs.push(schemaURI)
    return this
  }

  /**
   * Build the SchemaMeta object
   */
  build(): SchemaMeta {
    const result = SchemaMetaSchema.safeParse(this.data)

    if (!result.success) {
      const messages = result.error.issues.map((i) => `${i.path.join('.')}: ${i.message}`).join('\n')
      throw new SchemaMetaException(`Invalid SchemaMeta:\n${messages}`)
    }

    return result.data
  }
}

/**
 * Create a new SchemaMetaBuilder
 */
export function schemaMeta(): SchemaMetaBuilder {
  return new SchemaMetaBuilder()
}

/**
 * Create a new TrustAuthorityBuilder
 */
export function trustAuthority(): TrustAuthorityBuilder {
  return new TrustAuthorityBuilder()
}

/**
 * Create a new SchemaURIBuilder
 */
export function schemaURI(): SchemaURIBuilder {
  return new SchemaURIBuilder()
}
