import type { DocumentKind, SignatureResult } from '@owf/eudi-inspector'

/** An example of a page, made by scripts/generate-examples.mjs */
export interface Example {
  /** Opens the example as `#example=<id>` */
  id: string
  title: string
  /** What the example shows */
  description: string
  /** The values of the fields of the page: `doc` or `url`, and the options */
  values: Record<string, string>
  /** What the inspection reports, which a test checks: the codes of the findings and the signature results */
  expect?: { findings: string[]; signatures: SignatureResult['status'][] }
}

/** An example the start page offers */
export interface FeaturedExample {
  page: DocumentKind
  id: string
  title: string
}
