import {
  getPointerSigningCertificates,
  parseTrustedList,
  setTrustedListCrypto,
  type TrustedList,
  TrustedListProfiles,
  TSLType,
  validateTrustedList,
  validateTrustedListProfile,
  verifyEuLotlSignature,
  verifyTrustedListSignature,
} from '@owf/eudi-tl'
import { base64 } from '@owf/identity-common'
import { parseCertificate } from '@owf/x509'
import { type DocumentInput, errorMessage, toText } from './input'
import { type Inspection, InspectionError, type SignatureResult } from './inspection'
import { certificateName, parseKeys } from './signature'

/** Where the EU publishes its List of Trusted Lists */
export const EU_LOTL_URL = 'https://ec.europa.eu/tools/lotl/eu-lotl.xml'

export interface TrustedListOptions {
  /** Certificates the signer has to be one of, as PEM, base64 or hex */
  signers?: string
  /**
   * Check that the signer is one the EU LOTL lists for the territory of the list. Resolves
   * with the XML of the LOTL, which this module verifies.
   */
  loadLotl?: () => Promise<string>
}

const sameUri = (a: string | undefined, b: string | undefined) =>
  (a ?? '').replace(/^https?:\/\//, '') === (b ?? '').replace(/^https?:\/\//, '')

export const isLotl = (trustedList: TrustedList) => sameUri(trustedList.tslType, TSLType.EUlistofthelists)

const signerName = (signerCertificateBase64: string) => {
  try {
    return certificateName(parseCertificate(base64.decode(signerCertificateBase64)))
  } catch {
    return 'a certificate that cannot be parsed'
  }
}

async function verifySigner(
  xml: string,
  trustedList: TrustedList,
  options: TrustedListOptions
): Promise<SignatureResult> {
  if (isLotl(trustedList)) {
    await verifyEuLotlSignature(xml)
    return {
      status: 'valid',
      message: 'Valid, and signed with one of the EU LOTL signing certificates shipped with @owf/eudi-tl.',
    }
  }

  if (options.signers?.trim()) {
    let anchors: Uint8Array[]
    try {
      anchors = parseKeys(options.signers).flatMap((key) => (key.certificate ? [key.certificate.der] : []))
    } catch (error) {
      return { status: 'unverified', message: `Not verified: ${errorMessage(error)}` }
    }
    if (anchors.length === 0) {
      return { status: 'unverified', message: 'Not verified: the signer has to be given as certificates' }
    }
    const { signerCertificateBase64 } = await verifyTrustedListSignature(xml, { trustAnchors: anchors })
    return {
      status: 'valid',
      message: `Valid, and signed with a certificate you gave, ${signerName(signerCertificateBase64)}.`,
    }
  }

  if (options.loadLotl) {
    const territory = trustedList.schemeTerritory
    if (!territory) {
      return { status: 'unverified', message: 'Not verified: the list has no SchemeTerritory to look up in the LOTL' }
    }
    let lotlXml: string
    try {
      lotlXml = await options.loadLotl()
    } catch (error) {
      return { status: 'unverified', message: `Not verified: the EU LOTL cannot be loaded: ${errorMessage(error)}` }
    }
    await verifyEuLotlSignature(lotlXml)
    const anchors = getPointerSigningCertificates(parseTrustedList(lotlXml), { schemeTerritory: territory })
    if (anchors.length === 0) {
      return { status: 'invalid', message: `Invalid: the EU LOTL lists no signing certificate for ${territory}.` }
    }
    const { signerCertificateBase64 } = await verifyTrustedListSignature(xml, { trustAnchors: anchors })
    return {
      status: 'valid',
      message: `Valid, and signed with ${signerName(signerCertificateBase64)}, which the EU LOTL lists for ${territory}.`,
    }
  }

  const { signerCertificateBase64 } = await verifyTrustedListSignature(xml)
  return {
    status: 'valid',
    message: `Valid, signed with ${signerName(signerCertificateBase64)}. This proves integrity only: check the signer against the EU LOTL or a certificate to establish trust.`,
  }
}

/** Parse an ETSI TS 119 612 trusted list, check it and its profile, and verify its signature */
export function inspectTrustedList(input: DocumentInput, options: TrustedListOptions = {}): Inspection {
  const xml = toText(input)
  if (!xml) throw new InspectionError('There is nothing to inspect')
  let trustedList: TrustedList
  try {
    trustedList = parseTrustedList(xml)
  } catch (error) {
    throw new InspectionError(`This XML is not a parsable ETSI TS 119 612 trusted list: ${errorMessage(error)}`)
  }

  const structure = validateTrustedList(trustedList)
  const findings = [...structure.findings]
  const checks = ['ETSI TS 119 612 structure']
  const notes: string[] = []

  const profile = Object.values(TrustedListProfiles).find((rule) => sameUri(rule.tslType, trustedList.tslType))
  if (!profile) {
    notes.push(`No profile check, as the TSLType ${trustedList.tslType ?? '(none)'} is not one of a known profile`)
  } else if (!structure.valid) {
    notes.push(`The ${profile.name} profile is not checked, as the structure is invalid`)
  } else {
    checks.push(`${profile.name} profile`)
    findings.push(...validateTrustedListProfile(trustedList, profile).findings)
  }

  const facts: [string, string][] = []
  if (trustedList.schemeTerritory) facts.push(['Territory', trustedList.schemeTerritory])
  if (trustedList.pointersToOtherLists?.length) {
    facts.push(['Points to', `${trustedList.pointersToOtherLists.length} other lists`])
  }

  return {
    kind: 'trusted-list',
    title: isLotl(trustedList) ? 'EU List of Trusted Lists' : 'Trusted list (ETSI TS 119 612)',
    checks,
    notes,
    value: trustedList,
    findings,
    facts,
    signatures: [
      {
        label: 'Signature',
        verify: (crypto) => {
          // @owf/eudi-tl verifies XML signatures with one engine for the whole process
          setTrustedListCrypto(crypto)
          return verifySigner(xml, trustedList, options).catch(
            (error): SignatureResult => ({ status: 'invalid', message: `Invalid: ${errorMessage(error)}` })
          )
        },
      },
    ],
  }
}
