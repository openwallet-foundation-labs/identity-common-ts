import { type DocumentFormat, type DocumentInput, detect, type Inspection } from '@owf/eudi-inspector'
import { featured } from '../examples/featured'
import { pageUrl, showExamples, startPage } from '../page'
import { pageOf } from '../site'

// The over-asking check used to be a tab of this page
if (location.hash === '#over-asking') location.replace('over-asking/')

type Inspector = (input: DocumentInput) => Inspection

// The parsers of a format load when a document of it is inspected
const INSPECTORS: Record<DocumentFormat, () => Promise<Inspector>> = {
  'trusted-list': () => import('../formats/trusted-list').then((module) => module.inspectDocument),
  lote: () => import('../formats/lote').then((module) => module.inspectDocument),
  'registration-certificate': () =>
    import('../formats/registration-certificate').then((module) => module.inspectDocument),
  'access-certificate': () => import('../formats/access-certificate').then((module) => module.inspectDocument),
  'status-list': () => import('../formats/status-list').then((module) => module.inspectDocument),
  'sd-jwt': () => import('../formats/sd-jwt').then((module) => module.inspectDocument),
  mdoc: () => import('../formats/mdoc').then((module) => module.inspectDocument),
}

startPage({
  inspect: async ({ document }) => (await INSPECTORS[detect(document)]())(document),
  actions: (inspection, { linkTo }) => {
    const page = pageOf(inspection.kind)
    if (!page || inspection.kind === 'over-asking') return []
    return [linkTo(inspection.kind, `Open in the ${page.title} for more checks`)]
  },
})

showExamples(
  'Try an example',
  featured.map(({ page, id, title }) => ({
    title: `${title} (${pageOf(page)?.name ?? page})`,
    href: `${pageUrl(page)}#${new URLSearchParams({ example: id })}`,
  }))
)
