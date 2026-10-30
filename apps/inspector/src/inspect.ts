import { inspectAccessCertificate } from './access-certificate'
import { type DocumentFormat, detect } from './detect'
import type { DocumentInput } from './input'
import type { Inspection } from './inspection'
import { inspectLoTE } from './lote'
import { inspectMdoc } from './mdoc'
import { inspectRegistrationCertificate } from './registration-certificate'
import { inspectSdJwt } from './sd-jwt'
import { inspectStatusList } from './status-list'
import { inspectTrustedList } from './trusted-list'

export { type DocumentKind, type Inspection, InspectionError } from './inspection'

const INSPECTORS: Record<DocumentFormat, (input: DocumentInput) => Inspection> = {
  'trusted-list': inspectTrustedList,
  lote: inspectLoTE,
  'registration-certificate': inspectRegistrationCertificate,
  'access-certificate': inspectAccessCertificate,
  'status-list': inspectStatusList,
  'sd-jwt': inspectSdJwt,
  mdoc: inspectMdoc,
}

/**
 * Recognise the format of the input, parse it and check it against its specification,
 * with the defaults of each format.
 *
 * @throws InspectionError when the input is not one of the supported formats or does not parse
 */
export function inspect(input: DocumentInput): Inspection {
  return INSPECTORS[detect(input)](input)
}
