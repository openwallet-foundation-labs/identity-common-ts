import { type DocumentFormat, detect } from '../detect'
import type { DocumentInput } from '../input'
import type { Inspection } from '../inspection'
import { startPage } from '../page'
import { pageOf } from '../site'

// The over-asking check used to be a tab of this page
if (location.hash === '#over-asking') location.replace('over-asking/')

type Inspector = (input: DocumentInput) => Inspection

// The parsers of a format load when a document of it is inspected
const INSPECTORS: Record<DocumentFormat, () => Promise<Inspector>> = {
  'trusted-list': () => import('../trusted-list').then((module) => module.inspectTrustedList),
  lote: () => import('../lote').then((module) => module.inspectLoTE),
  'registration-certificate': () =>
    import('../registration-certificate').then((module) => module.inspectRegistrationCertificate),
  'access-certificate': () => import('../access-certificate').then((module) => module.inspectAccessCertificate),
  'status-list': () => import('../status-list').then((module) => module.inspectStatusList),
  'sd-jwt': () => import('../sd-jwt').then((module) => module.inspectSdJwt),
  mdoc: () => import('../mdoc').then((module) => module.inspectMdoc),
}

startPage({
  inspect: async ({ document }) => (await INSPECTORS[detect(document)]())(document),
  actions: (inspection, { linkTo }) => {
    const page = pageOf(inspection.kind)
    if (!page || inspection.kind === 'over-asking') return []
    return [linkTo(inspection.kind, `Open in the ${page.title} for more checks`)]
  },
})
