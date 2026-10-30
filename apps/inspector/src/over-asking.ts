import { getAccessCertificateSubjectIdentifier, parseAccessCertificate } from '@owf/eudi-access-certificate'
import {
  checkOverAsking,
  normalizeWRPRCPayload,
  type RegisteredCredential,
  validateWRPRC,
} from '@owf/eudi-registration-certificate'
import { decodeJwt, type Finding } from '@owf/identity-common'
import { type Inspection, InspectionError } from './inspect'

interface Request {
  /** How the request was given */
  form: string
  dcqlQuery: unknown
  /** Registration certificates found in `verifier_info` */
  registrationCertificates: string[]
  /** The leaf certificate of the `x5c` header of the request object, base64 DER */
  accessCertificate?: string
}

const JWS = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$/

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value)

const errorMessage = (error: unknown) => (error instanceof Error ? error.message : String(error))

const withPathPrefix = (prefix: string, findings: Finding[]): Finding[] =>
  findings.map((finding) => ({ ...finding, path: [prefix, ...finding.path] }))

function decode(jwt: string, what: string) {
  try {
    return decodeJwt<Record<string, unknown>, Record<string, unknown>>(jwt)
  } catch (error) {
    throw new InspectionError(`The ${what} cannot be decoded: ${errorMessage(error)}`)
  }
}

const typOf = (header: Record<string, unknown>) =>
  typeof header.typ === 'string' ? header.typ.toLowerCase().replace(/^application\//, '') : undefined

/** Read the request parameters, of an authorization request or the payload of a request object */
function fromParameters(parameters: Record<string, unknown>, form: string): Request {
  // A signed request of the Digital Credentials API carries the request object in `request`
  if (typeof parameters.request === 'string' && JWS.test(parameters.request)) {
    return fromRequestObject(parameters.request)
  }
  if (typeof parameters.request_uri === 'string') {
    throw new InspectionError(
      'The request passes its request object by reference (request_uri). Fetch the request object and paste it here.'
    )
  }

  let dcqlQuery = parameters.dcql_query
  if (typeof dcqlQuery === 'string') {
    try {
      dcqlQuery = JSON.parse(dcqlQuery)
    } catch (error) {
      throw new InspectionError(`dcql_query is not valid JSON: ${errorMessage(error)}`)
    }
  }
  if (dcqlQuery === undefined) throw new InspectionError('The request has no dcql_query')

  let verifierInfo = parameters.verifier_info
  if (typeof verifierInfo === 'string') {
    try {
      verifierInfo = JSON.parse(verifierInfo)
    } catch {
      verifierInfo = undefined
    }
  }
  const registrationCertificates = (Array.isArray(verifierInfo) ? verifierInfo : [])
    .map((entry) => (isRecord(entry) ? entry.data : undefined))
    .filter((data): data is string => typeof data === 'string' && JWS.test(data))
    .filter((data) => typOf(decode(data, 'verifier_info entry').header) === 'rc-wrp+jwt')

  return { form, dcqlQuery, registrationCertificates }
}

function fromRequestObject(jwt: string): Request {
  const { header, payload } = decode(jwt, 'request object')
  const request = fromParameters(payload, 'Request object')
  const x5c = header.x5c
  if (Array.isArray(x5c) && typeof x5c[0] === 'string') request.accessCertificate = x5c[0]
  return request
}

/**
 * Read an OpenID4VP request in any of the forms it is passed around in: a request object,
 * an authorization request as URL or JSON, a Digital Credentials API request, or only its
 * DCQL query.
 */
export function parseRequest(input: string): Request {
  const text = input.trim()
  if (!text) throw new InspectionError('Paste an OpenID4VP request')

  if (JWS.test(text)) return fromRequestObject(text)

  if (text.startsWith('{')) {
    let value: unknown
    try {
      value = JSON.parse(text)
    } catch (error) {
      throw new InspectionError(`The request is not valid JSON: ${errorMessage(error)}`)
    }
    if (!isRecord(value)) throw new InspectionError('The request must be a JSON object')
    if (Array.isArray(value.credentials)) return { form: 'DCQL query', dcqlQuery: value, registrationCertificates: [] }
    // A request of the Digital Credentials API wraps the parameters in `data`
    if (isRecord(value.data)) return fromParameters(value.data, 'Digital Credentials API request')
    return fromParameters(value, 'Authorization request')
  }

  let url: URL
  try {
    url = new URL(text)
  } catch {
    throw new InspectionError(
      'Unrecognised request. Expected a request object (JWT), an authorization request as URL or JSON, or a DCQL query.'
    )
  }
  return fromParameters(Object.fromEntries(url.searchParams), 'Authorization request URL')
}

/**
 * Check an OpenID4VP request against the registration certificate of the relying party:
 * the DCQL query against the registered credentials and claims, the registration
 * certificate itself, and, when the request object has an access certificate, the subject
 * of the registration certificate against it.
 *
 * @param requestInput The request, see {@link parseRequest}
 * @param registrationInput The registration certificate; optional when the request carries one in `verifier_info`
 */
export function checkRequest(requestInput: string, registrationInput = ''): Inspection {
  const request = parseRequest(requestInput)

  const pasted = registrationInput.trim()
  const registration = pasted || request.registrationCertificates[0]
  if (!registration) {
    throw new InspectionError(
      'There is no registration certificate: paste one, or check a request that carries one in verifier_info'
    )
  }
  if (!JWS.test(registration)) throw new InspectionError('The registration certificate must be a JWT')
  const { header, payload } = decode(registration, 'registration certificate')

  const notes = ['No signature is verified']
  const checks = ['DCQL query against the credentials of the registration certificate', 'Registration certificate']

  // The subject of the access certificate, which the registration certificate has to be for
  let subject: string | undefined
  if (request.accessCertificate) {
    try {
      subject = getAccessCertificateSubjectIdentifier(parseAccessCertificate(request.accessCertificate))
    } catch (error) {
      notes.push(`The access certificate of the request cannot be parsed: ${errorMessage(error)}`)
    }
  } else {
    notes.push('The registration certificate is not compared with an access certificate, as the request has no x5c')
  }
  const normalized = normalizeWRPRCPayload(payload)
  const registered = isRecord(normalized) ? normalized : {}
  const ownSubject = isRecord(registered.intermediary) ? registered.intermediary.sub : registered.sub
  if (subject) checks.push('Subject of the registration certificate against the access certificate')
  const certificate = validateWRPRC(header, payload, subject ?? (typeof ownSubject === 'string' ? ownSubject : ''))

  const credentials = Array.isArray(registered.credentials) ? (registered.credentials as RegisteredCredential[]) : []
  if (credentials.length === 0) notes.push('The registration certificate lists no credentials to request')
  const overAsking = checkOverAsking(request.dcqlQuery, credentials)

  const facts: [string, string][] = [
    ['Request', request.form],
    ['Registration certificate', pasted ? 'Pasted' : 'From verifier_info of the request'],
  ]
  const name = registered.name ?? registered.sub_ln ?? registered.sub
  if (typeof name === 'string') facts.push(['Relying party', name])
  const overAskingErrors = overAsking.findings.filter((finding) => finding.severity === 'error').length
  facts.push([
    'Over-asking',
    overAskingErrors === 0
      ? 'None, the request stays within the registration'
      : `${overAskingErrors} ${overAskingErrors === 1 ? 'request goes' : 'requests go'} beyond the registration`,
  ])

  return {
    kind: 'over-asking',
    title: 'OpenID4VP request against the registration certificate',
    checks,
    notes,
    facts,
    value: { dcql_query: request.dcqlQuery, registration_certificate: { header, payload } },
    findings: [
      ...withPathPrefix('dcql_query', overAsking.findings),
      ...withPathPrefix('registration_certificate', certificate.findings),
    ],
  }
}
