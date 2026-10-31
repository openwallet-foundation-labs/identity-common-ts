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

/** The outcome of a signature check: `unverified` when it could not be checked, e.g. for want of a key */
export interface SignatureResult {
  status: 'valid' | 'invalid' | 'unverified'
  message: string
}

/** A signature to verify, separately as it is asynchronous */
export interface SignatureCheck {
  /** What is signed, e.g. "Signature" or "Key Binding JWT" */
  label: string
  /** Verify the signature with a Web Crypto implementation, e.g. `globalThis.crypto` */
  verify: (crypto: Crypto) => Promise<SignatureResult>
}

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
  signatures?: SignatureCheck[]
}

/** The input could not be recognised or parsed */
export class InspectionError extends Error {}
