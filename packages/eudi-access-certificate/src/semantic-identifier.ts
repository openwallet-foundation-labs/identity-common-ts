import type { SemanticIdentifier } from './types'

const SEMANTIC_IDENTIFIER = /^([A-Z]{3}|[A-Z]{2}:)([A-Z]{2})(?:\+([A-Z0-9]{1,3}))?-(.+)$/

/**
 * Parse a semantic identifier per ETSI EN 319 412-1 clauses 5.1.3 and 5.1.4
 * (`<type><country>[+<subdivision>]-<identifier>`). Returns `undefined` when the
 * value does not follow that structure.
 */
export function parseSemanticIdentifier(value: string): SemanticIdentifier | undefined {
  const match = value.match(SEMANTIC_IDENTIFIER)
  if (!match) return undefined
  const [, type, countryCode, subdivision, identifier] = match
  return { value, type, countryCode, subdivision, identifier }
}

/** Identity type references for legal persons (ETSI EN 319 412-1 clause 5.1.4) */
export const LEGAL_PERSON_IDENTIFIER_TYPES = ['VAT', 'NTR', 'PSD', 'LEI'] as const

/** Identity type references for natural persons (ETSI EN 319 412-1 clause 5.1.3) */
export const NATURAL_PERSON_IDENTIFIER_TYPES = ['PAS', 'IDC', 'PNO', 'TAX', 'TIN'] as const
