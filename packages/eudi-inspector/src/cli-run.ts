import { readFile, stat } from 'node:fs/promises'
import { parseArgs } from 'node:util'
import { base64url } from '@owf/identity-common'
import { type DocumentFormat, detect } from './detect'
import { type DocumentInput, errorMessage } from './input'
import { INSPECTORS, type InspectOptions } from './inspect'
import { type Inspection, InspectionError } from './inspection'
import { checkRequest } from './over-asking'
import { type InspectionReport, report } from './report'
import { MAX_LINK_LENGTH, type SharedValue, toFragment } from './share'
import { formatReport } from './text'
import { EU_LOTL_URL } from './trusted-list'

/** What the command line tool reads from and writes to, so it can run in tests */
export interface CliEnvironment {
  stdout: (text: string) => void
  stderr: (text: string) => void
  readStdin: () => Promise<Uint8Array>
  fetch: typeof fetch
  /** The Web Crypto implementation to verify signatures with */
  crypto: Crypto
  color: boolean
  version: string
}

/** The exit status: no errors, errors or an invalid signature, or input that cannot be read */
export const EXIT = { OK: 0, FAILED: 1, UNREADABLE: 2 } as const

/** Where the web pages of the inspector are published */
export const WEB_URL = 'https://openwallet-foundation-labs.github.io/identity-common-ts/'

const FORMATS = Object.keys(INSPECTORS) as DocumentFormat[]

const HELP = `Parse EUDI documents and check each element against its specification.

Usage:
  eudi-inspect [options] <document...>
  eudi-inspect over-asking <request> [--registration <certificate>]

A document is a file, an http(s) URL, - for standard input, or the document itself.
Keys and certificates are given as a file or as text.

Options:
  -f, --format <format>            ${FORMATS.join(', ')}.
                                   Recognised from the document when left out
  -k, --key <key>                  Key of the signer as JWK, JWK Set or PEM. A certificate
                                   is the trust anchor the x5c chain has to lead to
      --nonce <nonce>              Nonce the Key Binding JWT of an SD-JWT has to hold
      --aud <aud>                  Audience the Key Binding JWT of an SD-JWT has to be for
      --uri <uri>                  uri of the reference sub of a status list has to equal
      --index <index>              Look up the status at an index of a status list
      --access-certificate <cert>  Access certificate a registration certificate has to be for
      --issuer <cert>              Certificate of the CA that issued an access certificate
      --signers <certs>            Certificates a trusted list has to be signed with
      --lotl                       Check the signer of a trusted list against the EU LOTL,
                                   fetched from ${EU_LOTL_URL}
      --lotl-source <file|url>     Read the EU LOTL from here instead, implies --lotl
      --registration <cert>        Registration certificate to check a request against
      --json                       Print the result as JSON, with the parsed document
      --strict                     Also fail on warnings and on signatures not verified
      --link                       Print a link that opens the document in the web page
  -h, --help                       Show this help
  -v, --version                    Show the version

Exit status: 0 without errors, 1 with errors or an invalid signature, 2 when a document
cannot be read.`

const OPTIONS = {
  format: { type: 'string', short: 'f' },
  key: { type: 'string', short: 'k' },
  nonce: { type: 'string' },
  aud: { type: 'string' },
  uri: { type: 'string' },
  index: { type: 'string' },
  'access-certificate': { type: 'string' },
  issuer: { type: 'string' },
  signers: { type: 'string' },
  lotl: { type: 'boolean' },
  'lotl-source': { type: 'string' },
  registration: { type: 'string' },
  json: { type: 'boolean' },
  strict: { type: 'boolean' },
  link: { type: 'boolean' },
  help: { type: 'boolean', short: 'h' },
  version: { type: 'boolean', short: 'v' },
} as const

type Values = ReturnType<typeof parseArgs<{ options: typeof OPTIONS; allowPositionals: true }>>['values']

/** A command line error, reported without a stack trace */
class UsageError extends Error {}

const isUrl = (text: string) => /^https?:\/\//i.test(text)

async function isFile(path: string): Promise<boolean> {
  try {
    return (await stat(path)).isFile()
  } catch {
    return false
  }
}

interface Source {
  input: DocumentInput
  /** How to name it to the user */
  name: string
  url?: string
}

async function readSource(argument: string, environment: CliEnvironment): Promise<Source> {
  if (argument === '-') return { input: await environment.readStdin(), name: 'standard input' }
  if (isUrl(argument)) {
    let response: Response
    try {
      response = await environment.fetch(argument)
    } catch (error) {
      throw new InspectionError(`${argument} cannot be fetched: ${errorMessage(error)}`)
    }
    if (!response.ok) throw new InspectionError(`${argument} answered ${response.status} ${response.statusText}`)
    return { input: new Uint8Array(await response.arrayBuffer()), name: argument, url: argument }
  }
  if (await isFile(argument)) return { input: new Uint8Array(await readFile(argument)), name: argument }
  return { input: argument, name: 'the argument' }
}

/** An option that is a file or the text itself */
async function readOption(value: string | undefined): Promise<string | undefined> {
  if (value === undefined) return undefined
  return (await isFile(value)) ? readFile(value, 'utf8') : value
}

async function inspectOptions(values: Values, environment: CliEnvironment): Promise<InspectOptions> {
  const lotlSource = values['lotl-source'] ?? (values.lotl ? EU_LOTL_URL : undefined)
  let lotl: Promise<string> | undefined
  const loadLotl = lotlSource
    ? () => {
        lotl ??= readSource(lotlSource, environment).then(({ input }) =>
          typeof input === 'string' ? input : new TextDecoder().decode(input)
        )
        return lotl
      }
    : undefined
  return {
    key: await readOption(values.key),
    nonce: values.nonce,
    aud: values.aud,
    uri: values.uri,
    accessCertificate: await readOption(values['access-certificate']),
    issuer: await readOption(values.issuer),
    signers: await readOption(values.signers),
    loadLotl,
  }
}

/** The document as text; binary documents as base64url, which the web pages read as well */
function documentText(input: DocumentInput): string {
  if (typeof input === 'string') return input
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(input)
  } catch {
    return base64url.encode(input)
  }
}

/** A link to the web page of the format, with the input in the fragment */
async function webLink(
  page: string,
  source: Source | undefined,
  values: Values,
  options: InspectOptions
): Promise<string | undefined> {
  const shared: SharedValue[] = []
  if (source?.url) shared.push({ name: 'url', value: source.url, compress: false })
  else if (source) shared.push({ name: 'doc', value: documentText(source.input), compress: true })
  shared.push(
    { name: 'key', value: options.key ?? '', compress: true },
    { name: 'nonce', value: options.nonce ?? '', compress: false },
    { name: 'aud', value: options.aud ?? '', compress: false },
    { name: 'uri', value: options.uri ?? '', compress: false },
    { name: 'access', value: options.accessCertificate ?? '', compress: true },
    { name: 'issuer', value: options.issuer ?? '', compress: true },
    { name: 'signers', value: options.signers ?? '', compress: true },
    { name: 'lotl', value: options.loadLotl ? '1' : '', compress: false },
    { name: 'lookup', value: values.index ?? '', compress: false }
  )
  const link = `${WEB_URL}${page}/#${await toFragment(shared)}`
  return link.length <= MAX_LINK_LENGTH ? link : undefined
}

function exitStatus(result: InspectionReport, strict: boolean): number {
  if (!result.valid) return EXIT.FAILED
  if (strict && (result.findings.length > 0 || result.signatures.some((signature) => signature.status !== 'valid'))) {
    return EXIT.FAILED
  }
  return EXIT.OK
}

interface Outcome {
  status: number
  source: string
  report?: InspectionReport
  lookup?: { index: string; status: string }
  link?: string
  error?: string
}

async function inspectSource(
  argument: string,
  values: Values,
  options: InspectOptions,
  environment: CliEnvironment
): Promise<Outcome> {
  let source: Source | undefined
  let inspection: Inspection
  try {
    source = await readSource(argument, environment)
    const format = (values.format as DocumentFormat | undefined) ?? detect(source.input)
    inspection = INSPECTORS[format](source.input, options)
  } catch (error) {
    const message = error instanceof InspectionError ? error.message : `Unexpected error: ${errorMessage(error)}`
    const hint =
      source?.name === 'the argument' && !/\s/.test(argument) && argument.length < 256
        ? ` There is no file named ${argument} either.`
        : ''
    return { status: EXIT.UNREADABLE, source: source?.name ?? argument, error: `${message}${hint}` }
  }

  const result = await report(inspection, environment.crypto)
  const outcome: Outcome = { status: exitStatus(result, values.strict ?? false), source: source.name, report: result }
  if (values.index !== undefined && inspection.lookup) {
    outcome.lookup = { index: values.index, status: inspection.lookup.find(values.index) }
  }
  if (values.link) outcome.link = (await webLink(inspection.kind, source, values, options)) ?? 'too large for a link'
  return outcome
}

async function checkOverAsking(positionals: string[], values: Values, environment: CliEnvironment): Promise<Outcome> {
  const [argument] = positionals
  if (!argument) throw new UsageError('over-asking needs the request')
  try {
    const source = await readSource(argument, environment)
    const request = typeof source.input === 'string' ? source.input : new TextDecoder().decode(source.input)
    const registration = (await readOption(values.registration)) ?? ''
    const result = await report(checkRequest(request, registration), environment.crypto)
    const outcome: Outcome = { status: exitStatus(result, values.strict ?? false), source: source.name, report: result }
    if (values.link) {
      const fragment = await toFragment([
        { name: 'request', value: request, compress: true },
        { name: 'registration', value: registration, compress: true },
      ])
      const link = `${WEB_URL}over-asking/#${fragment}`
      outcome.link = link.length <= MAX_LINK_LENGTH ? link : 'too large for a link'
    }
    return outcome
  } catch (error) {
    const message = error instanceof InspectionError ? error.message : `Unexpected error: ${errorMessage(error)}`
    return { status: EXIT.UNREADABLE, source: argument, error: message }
  }
}

function print(outcomes: Outcome[], values: Values, environment: CliEnvironment): void {
  if (values.json) {
    const entries = outcomes.map(({ source, report: result, lookup, link, error }) =>
      error ? { source, error } : { source, ...result, ...(lookup ? { lookup } : {}), ...(link ? { link } : {}) }
    )
    environment.stdout(JSON.stringify(entries.length === 1 ? entries[0] : entries, null, 2))
    return
  }
  outcomes.forEach((outcome, index) => {
    if (index > 0) environment.stdout('')
    if (outcome.error) {
      environment.stderr(`${outcome.source}: ${outcome.error}`)
      return
    }
    if (!outcome.report) return
    const extra: [string, string][] = []
    if (outcome.lookup) extra.push([`Status at ${outcome.lookup.index}`, outcome.lookup.status])
    if (outcome.link) extra.push(['Link', outcome.link])
    environment.stdout(formatReport(outcome.report, { source: outcome.source, color: environment.color, extra }))
  })
}

/**
 * Run the command line tool.
 *
 * @returns The exit status, see {@link EXIT}
 */
export async function run(args: string[], environment: CliEnvironment): Promise<number> {
  let values: Values
  let positionals: string[]
  try {
    ;({ values, positionals } = parseArgs({ args, options: OPTIONS, allowPositionals: true, strict: true }))
    if (values.format && !FORMATS.includes(values.format as DocumentFormat)) {
      throw new UsageError(`Unknown format ${values.format}. Expected one of ${FORMATS.join(', ')}.`)
    }
  } catch (error) {
    environment.stderr(`${errorMessage(error)}\n\nRun eudi-inspect --help for the options.`)
    return EXIT.UNREADABLE
  }

  if (values.help) {
    environment.stdout(HELP)
    return EXIT.OK
  }
  if (values.version) {
    environment.stdout(environment.version)
    return EXIT.OK
  }
  if (positionals.length === 0) {
    environment.stderr(`${HELP}\n\nGive a document to inspect.`)
    return EXIT.UNREADABLE
  }

  let outcomes: Outcome[]
  try {
    if (positionals[0] === 'over-asking') {
      outcomes = [await checkOverAsking(positionals.slice(1), values, environment)]
    } else {
      const options = await inspectOptions(values, environment)
      outcomes = []
      for (const argument of positionals) outcomes.push(await inspectSource(argument, values, options, environment))
    }
  } catch (error) {
    if (!(error instanceof UsageError)) throw error
    environment.stderr(error.message)
    return EXIT.UNREADABLE
  }

  print(outcomes, values, environment)
  return Math.max(...outcomes.map((outcome) => outcome.status))
}
