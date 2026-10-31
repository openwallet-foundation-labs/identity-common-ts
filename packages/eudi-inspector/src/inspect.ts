import { type AccessCertificateOptions, inspectAccessCertificate } from './access-certificate'
import { type DocumentFormat, detect } from './detect'
import type { DocumentInput } from './input'
import type { Inspection } from './inspection'
import { inspectLoTE, type LoTEOptions } from './lote'
import { inspectMdoc } from './mdoc'
import { inspectRegistrationCertificate, type RegistrationCertificateOptions } from './registration-certificate'
import { inspectSdJwt, type SdJwtOptions } from './sd-jwt'
import { inspectStatusList, type StatusListOptions } from './status-list'
import { inspectTrustedList, type TrustedListOptions } from './trusted-list'

/** The options of every format; each format reads the ones it has */
export interface InspectOptions
  extends TrustedListOptions,
    LoTEOptions,
    RegistrationCertificateOptions,
    AccessCertificateOptions,
    StatusListOptions,
    SdJwtOptions {}

/** The inspection of each format */
export const INSPECTORS: Record<DocumentFormat, (input: DocumentInput, options?: InspectOptions) => Inspection> = {
  'trusted-list': inspectTrustedList,
  lote: inspectLoTE,
  'registration-certificate': inspectRegistrationCertificate,
  'access-certificate': inspectAccessCertificate,
  'status-list': inspectStatusList,
  'sd-jwt': inspectSdJwt,
  mdoc: (input) => inspectMdoc(input),
}

/**
 * Parse a document and check it against its specification.
 *
 * @param format The format of the document; recognised from the input when left out
 * @throws InspectionError when the input is not one of the supported formats or does not parse
 */
export function inspect(input: DocumentInput, options: InspectOptions = {}, format?: DocumentFormat): Inspection {
  return INSPECTORS[format ?? detect(input)](input, options)
}
