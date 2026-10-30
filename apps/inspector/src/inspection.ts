import type { Finding } from '@owf/identity-common'

export type DocumentKind =
  | 'trusted-list'
  | 'lote'
  | 'registration-certificate'
  | 'access-certificate'
  | 'status-list'
  | 'sd-jwt'
  | 'mdoc'
  | 'over-asking'

export interface Inspection {
  kind: DocumentKind
  /** What the input was recognised as */
  title: string
  /** The checks that ran */
  checks: string[]
  /** What was not checked */
  notes: string[]
  /** The parsed document, which the paths of the findings point into */
  value: unknown
  findings: Finding[]
  /** Further facts about the document, as label and value */
  facts?: [string, string][]
  /** Look something up in the document, e.g. the status at an index of a status list */
  lookup?: { label: string; placeholder: string; find: (input: string) => string }
  /**
   * Verify the signature, separately as it is asynchronous. Resolves with a description of
   * what was established, rejects when the signature is missing or invalid.
   */
  verifySignature?: () => Promise<string>
}

/** The input could not be recognised or parsed */
export class InspectionError extends Error {}
