import {
  checkRequest,
  type DocumentInput,
  type DocumentKind,
  EU_LOTL_URL,
  type Inspection,
  inspectAccessCertificate,
  inspectLoTE,
  inspectMdoc,
  inspectRegistrationCertificate,
  inspectSdJwt,
  inspectStatusList,
  inspectTrustedList,
} from '@owf/eudi-inspector'

// How each page inspects what its form holds, apart from the page, so the examples can be tested

export interface PageInput {
  /** The document, empty on a page without a document field */
  document: DocumentInput
  /** The values of the other fields of the form by name, "1" for a checked checkbox */
  fields: Record<string, string>
}

let lotl: Promise<string> | undefined

/** The EU LOTL, fetched once */
function fetchLotl(): Promise<string> {
  lotl ??= fetch(EU_LOTL_URL, { credentials: 'omit' }).then(async (response) => {
    if (!response.ok) throw new Error(`${EU_LOTL_URL} answered ${response.status}`)
    return response.text()
  })
  // Try again next time
  lotl.catch(() => {
    lotl = undefined
  })
  return lotl
}

export const inspectTrustedListPage = ({ document, fields }: PageInput) =>
  inspectTrustedList(document, { signers: fields.signers, loadLotl: fields.lotl ? fetchLotl : undefined })

export const inspectLoTEPage = ({ document, fields }: PageInput) => inspectLoTE(document, { key: fields.key })

export const inspectRegistrationCertificatePage = ({ document, fields }: PageInput) =>
  inspectRegistrationCertificate(document, { accessCertificate: fields.access, key: fields.key })

export const inspectAccessCertificatePage = ({ document, fields }: PageInput) =>
  inspectAccessCertificate(document, { issuer: fields.issuer })

export const inspectStatusListPage = ({ document, fields }: PageInput) =>
  inspectStatusList(document, { uri: fields.uri, key: fields.key })

export const inspectSdJwtPage = ({ document, fields }: PageInput) =>
  inspectSdJwt(document, { key: fields.key, nonce: fields.nonce, aud: fields.aud })

export const inspectMdocPage = ({ document }: PageInput) => inspectMdoc(document)

export const checkRequestPage = ({ fields }: PageInput) => checkRequest(fields.request ?? '', fields.registration ?? '')

/** The inspection of each page */
export const PAGE_INSPECTORS: Record<DocumentKind, (input: PageInput) => Inspection> = {
  'trusted-list': inspectTrustedListPage,
  lote: inspectLoTEPage,
  'registration-certificate': inspectRegistrationCertificatePage,
  'access-certificate': inspectAccessCertificatePage,
  'status-list': inspectStatusListPage,
  'sd-jwt': inspectSdJwtPage,
  mdoc: inspectMdocPage,
  'over-asking': checkRequestPage,
}
