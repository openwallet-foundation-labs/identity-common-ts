import { report } from '@owf/eudi-inspector'
import { describe, expect, it } from 'vitest'
import type { Example } from '../example'
import { examples as accessCertificate } from '../examples/access-certificate'
import { featured } from '../examples/featured'
import { examples as lote } from '../examples/lote'
import { examples as mdoc } from '../examples/mdoc'
import { examples as overAsking } from '../examples/over-asking'
import { examples as registrationCertificate } from '../examples/registration-certificate'
import { examples as sdJwt } from '../examples/sd-jwt'
import { examples as statusList } from '../examples/status-list'
import { examples as trustedList } from '../examples/trusted-list'
import { PAGE_INSPECTORS } from '../inspectors'

const PAGES = {
  'trusted-list': trustedList,
  lote,
  'registration-certificate': registrationCertificate,
  'access-certificate': accessCertificate,
  'status-list': statusList,
  'sd-jwt': sdJwt,
  mdoc,
  'over-asking': overAsking,
} satisfies Record<keyof typeof PAGE_INSPECTORS, Example[]>

// The examples of each page show what their descriptions say, so they are run as the page runs them
describe('examples', () => {
  for (const [page, examples] of Object.entries(PAGES)) {
    for (const example of examples) {
      // An example of a URL fetches it, so it is not run here
      it.skipIf(example.values.url !== undefined)(`${page}: ${example.title}`, async () => {
        const { doc = '', ...fields } = example.values
        const result = await report(PAGE_INSPECTORS[page as keyof typeof PAGES]({ document: doc, fields }), crypto)
        expect({
          findings: result.findings.map((finding) => finding.code).sort(),
          signatures: result.signatures.map((signature) => signature.status),
        }).toEqual({
          findings: [...(example.expect?.findings ?? [])].sort(),
          signatures: example.expect?.signatures ?? [],
        })
      })
    }
  }

  it('features examples that exist', () => {
    for (const { page, id } of featured) {
      expect(PAGES[page].map((example) => example.id)).toContain(id)
    }
  })
})
