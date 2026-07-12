import { describe, expect, it } from 'vitest'
import { assertValidSchemaMeta, validateSchemaMeta } from '../validator'

const RULEBOOK_INTEGRITY = 'sha256-cJe/IG7DijmXd2FpecyWJVnZ9EuKKprly5auxGm1uIw='
const SCHEMA_INTEGRITY = 'sha256-M8H+reBt9Nr/s8CRicJrthAnk7UdWyTyONW0N8Z/Axw='

const validSchemaMeta = {
  id: 'https://example.com/attestations/test',
  iat: 1735000000,
  version: '1.0.0',
  rulebookURI: 'https://example.com/rulebook.md',
  rulebookIntegrity: RULEBOOK_INTEGRITY,
  attestationLoS: 'iso_18045_basic',
  bindingType: 'key',
  schemaURIs: [
    {
      formatIdentifier: 'dc+sd-jwt',
      uri: 'https://example.com/schema.json',
      integrity: SCHEMA_INTEGRITY,
      meta: { vct: 'eu.europa.ec.eudi.pid.1' },
    },
  ],
}

describe('validateSchemaMeta', () => {
  it('validates a valid SchemaMeta', () => {
    const result = validateSchemaMeta(validSchemaMeta)
    expect(result.valid).toBe(true)
    expect(result.errors).toHaveLength(0)
  })

  it('accepts etsi_tl trusted authorities', () => {
    const result = validateSchemaMeta({
      ...validSchemaMeta,
      trustedAuthorities: [{ frameworkType: 'etsi_tl', value: 'https://example.com/trust-list.jws' }],
    })
    expect(result.valid).toBe(true)
  })

  it('rejects missing rulebookIntegrity', () => {
    const { rulebookIntegrity, ...invalid } = validSchemaMeta
    const result = validateSchemaMeta(invalid)
    expect(result.valid).toBe(false)
  })

  it('rejects schemaURI missing integrity', () => {
    const result = validateSchemaMeta({
      ...validSchemaMeta,
      schemaURIs: [{ formatIdentifier: 'dc+sd-jwt', uri: 'https://example.com/schema.json', meta: { vct: 'x' } }],
    })
    expect(result.valid).toBe(false)
  })

  it('rejects non-sha256 SRI integrity', () => {
    const result = validateSchemaMeta({
      ...validSchemaMeta,
      schemaURIs: [{ ...validSchemaMeta.schemaURIs[0], integrity: 'sha512-abc' }],
    })
    expect(result.valid).toBe(false)
  })

  it('rejects invalid id URL', () => {
    const result = validateSchemaMeta({ ...validSchemaMeta, id: 'not-a-url' })
    expect(result.valid).toBe(false)
  })

  it('rejects non-integer iat', () => {
    const result = validateSchemaMeta({ ...validSchemaMeta, iat: 123.5 })
    expect(result.valid).toBe(false)
  })

  it('rejects invalid frameworkType in trustedAuthorities', () => {
    const result = validateSchemaMeta({
      ...validSchemaMeta,
      trustedAuthorities: [{ frameworkType: 'aki', value: 'test' }],
    })
    expect(result.valid).toBe(false)
  })

  it('rejects duplicate formatIdentifier values in schemaURIs', () => {
    const result = validateSchemaMeta({
      ...validSchemaMeta,
      schemaURIs: [
        validSchemaMeta.schemaURIs[0],
        {
          formatIdentifier: 'dc+sd-jwt',
          uri: 'https://example.com/schema2.json',
          integrity: SCHEMA_INTEGRITY,
          meta: { vct: 'eu.europa.ec.eudi.pid.2' },
        },
      ],
    })
    expect(result.valid).toBe(false)
  })

  it('accepts both supported formats with detailed meta', () => {
    const result = validateSchemaMeta({
      ...validSchemaMeta,
      schemaURIs: [
        {
          formatIdentifier: 'dc+sd-jwt',
          uri: 'https://example.org/schemas/pid.json',
          integrity: SCHEMA_INTEGRITY,
          meta: { vct: 'eu.europa.ec.eudi.pid.1' },
        },
        {
          formatIdentifier: 'mso_mdoc',
          uri: 'https://example.org/schemas/mdl.json',
          integrity: SCHEMA_INTEGRITY,
          meta: { doctype_value: 'org.iso.18013.5.1.mDL' },
        },
      ],
    })
    expect(result.valid).toBe(true)
  })
})

describe('assertValidSchemaMeta', () => {
  it('does not throw for valid SchemaMeta', () => {
    expect(() => assertValidSchemaMeta(validSchemaMeta)).not.toThrow()
  })

  it('throws SchemaMetaException for invalid SchemaMeta', () => {
    expect(() => assertValidSchemaMeta({})).toThrow('Invalid SchemaMeta')
  })

  it('narrows the type after assertion', () => {
    const data: unknown = validSchemaMeta
    assertValidSchemaMeta(data)
    expect(data.version).toBe('1.0.0')
    expect(data.schemaURIs[0].formatIdentifier).toBe('dc+sd-jwt')
  })
})
