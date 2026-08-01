/**
 * Regenerates `src/__tests__/fixtures.mts`: two small synthetic ETSI TS 119 612
 * trusted lists (an unsigned one exercising the parser and a signed one
 * exercising XAdES signature verification) plus the test certificates they
 * embed. Run from the package directory:
 *
 *   pnpm exec tsx scripts/generate-test-fixtures.mts
 *
 * The signed sample is produced once here so the test suite only ever verifies
 * signatures — it never signs. After regenerating, run `pnpm style:fix` at the
 * repo root.
 */
import { mkdirSync, writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import * as x509 from '@peculiar/x509'
import { DOMParser, XMLSerializer, type Node as XmldomNode } from '@xmldom/xmldom'
import * as xadesjs from 'xadesjs'
import * as xpath from 'xpath'
import { verifyTrustedListSignature } from '../src/verify'

const crypto = globalThis.crypto
x509.cryptoProvider.set(crypto as Crypto)
xadesjs.Application.setEngine('WebCrypto', crypto)
xadesjs.setNodeDependencies({ DOMParser, XMLSerializer, xpath })

const signingAlgorithm = {
  name: 'RSASSA-PKCS1-v1_5',
  hash: 'SHA-256',
  publicExponent: new Uint8Array([1, 0, 1]),
  modulusLength: 2048,
}

interface TestIdentity {
  keys: CryptoKeyPair
  certificateBase64: string
  skiHex: string
  skiBase64: string
}

async function createSelfSigned(subject: string): Promise<TestIdentity> {
  const keys = (await crypto.subtle.generateKey(signingAlgorithm, true, ['sign', 'verify'])) as CryptoKeyPair
  const certificate = await x509.X509CertificateGenerator.createSelfSigned({
    serialNumber: `0${Math.floor(Math.random() * 0xffffff).toString(16)}`,
    name: subject,
    notBefore: new Date('2025-01-01T00:00:00Z'),
    notAfter: new Date('2045-01-01T00:00:00Z'),
    signingAlgorithm,
    keys,
    extensions: [
      new x509.BasicConstraintsExtension(true, undefined, true),
      new x509.KeyUsagesExtension(x509.KeyUsageFlags.digitalSignature | x509.KeyUsageFlags.keyCertSign, true),
      await x509.SubjectKeyIdentifierExtension.create(keys.publicKey, false, crypto as Crypto),
    ],
  })
  const skiHex = certificate.getExtension(x509.SubjectKeyIdentifierExtension)?.keyId ?? ''
  const skiBytes = Uint8Array.from(skiHex.match(/../g)?.map((b) => Number.parseInt(b, 16)) ?? [])
  return {
    keys,
    certificateBase64: certificate.toString('base64'),
    skiHex: skiHex.toLowerCase(),
    skiBase64: btoa(String.fromCharCode(...skiBytes)),
  }
}

function unsignedTsl(caCert: TestIdentity, tsaCert: TestIdentity): string {
  return `<?xml version="1.0" encoding="UTF-8"?>
<tsl:TrustServiceStatusList xmlns:tsl="http://uri.etsi.org/02231/v2#" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" TSLTag="http://uri.etsi.org/19612/TSLTag" Id="TrustServiceStatusList">
  <tsl:SchemeInformation>
    <tsl:TSLVersionIdentifier>5</tsl:TSLVersionIdentifier>
    <tsl:TSLSequenceNumber>42</tsl:TSLSequenceNumber>
    <tsl:TSLType>http://uri.etsi.org/TrstSvc/TrustedList/TSLType/EUgeneric</tsl:TSLType>
    <tsl:SchemeOperatorName>
      <tsl:Name xml:lang="es">Operador de Esquema de Prueba</tsl:Name>
      <tsl:Name xml:lang="en">Test Scheme Operator</tsl:Name>
    </tsl:SchemeOperatorName>
    <tsl:SchemeTerritory>ES</tsl:SchemeTerritory>
    <tsl:ListIssueDateTime>2025-01-15T00:00:00Z</tsl:ListIssueDateTime>
    <tsl:NextUpdate>
      <tsl:dateTime>2025-07-15T00:00:00Z</tsl:dateTime>
    </tsl:NextUpdate>
    <tsl:PointersToOtherTSL>
      <tsl:OtherTSLPointer>
        <tsl:ServiceDigitalIdentities/>
        <tsl:TSLLocation>https://ec.europa.eu/tools/lotl/eu-lotl.xml</tsl:TSLLocation>
        <tsl:AdditionalInformation>
          <tsl:OtherInformation>
            <tsl:TSLType>http://uri.etsi.org/TrstSvc/TrustedList/TSLType/EUlistofthelists</tsl:TSLType>
          </tsl:OtherInformation>
          <tsl:OtherInformation>
            <tsl:SchemeTerritory>EU</tsl:SchemeTerritory>
          </tsl:OtherInformation>
        </tsl:AdditionalInformation>
      </tsl:OtherTSLPointer>
    </tsl:PointersToOtherTSL>
  </tsl:SchemeInformation>
  <tsl:TrustServiceProviderList>
    <tsl:TrustServiceProvider>
      <tsl:TSPInformation>
        <tsl:TSPName>
          <tsl:Name xml:lang="en">Test Qualified CA S.A.</tsl:Name>
        </tsl:TSPName>
      </tsl:TSPInformation>
      <tsl:TSPServices>
        <tsl:TSPService>
          <tsl:ServiceInformation>
            <tsl:ServiceTypeIdentifier>http://uri.etsi.org/TrstSvc/Svctype/CA/QC</tsl:ServiceTypeIdentifier>
            <tsl:ServiceName>
              <tsl:Name xml:lang="en">Test QC CA</tsl:Name>
            </tsl:ServiceName>
            <tsl:ServiceDigitalIdentity>
              <tsl:DigitalId>
                <tsl:X509Certificate>${caCert.certificateBase64}</tsl:X509Certificate>
              </tsl:DigitalId>
              <tsl:DigitalId>
                <tsl:X509SubjectName>CN=Test QC CA, O=Test Qualified CA S.A., C=ES</tsl:X509SubjectName>
              </tsl:DigitalId>
              <tsl:DigitalId>
                <tsl:X509SKI>${caCert.skiBase64}</tsl:X509SKI>
              </tsl:DigitalId>
            </tsl:ServiceDigitalIdentity>
            <tsl:ServiceStatus>http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted</tsl:ServiceStatus>
            <tsl:StatusStartingTime>2020-03-01T12:00:00Z</tsl:StatusStartingTime>
            <tsl:ServiceInformationExtensions>
              <tsl:Extension Critical="true">
                <tsl:Qualifications xmlns:tsl="http://uri.etsi.org/TrstSvc/SvcInfoExt/eSigDir-1999-93-EC-TrustedList/#">
                  <tsl:QualificationElement>
                    <tsl:Qualifiers>
                      <tsl:Qualifier uri="http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCWithSSCD"/>
                      <tsl:Qualifier uri="http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCStatement"/>
                    </tsl:Qualifiers>
                  </tsl:QualificationElement>
                </tsl:Qualifications>
              </tsl:Extension>
            </tsl:ServiceInformationExtensions>
          </tsl:ServiceInformation>
          <tsl:ServiceHistory>
            <tsl:ServiceHistoryInstance>
              <tsl:ServiceTypeIdentifier>http://uri.etsi.org/TrstSvc/Svctype/CA/QC</tsl:ServiceTypeIdentifier>
              <tsl:ServiceName>
                <tsl:Name xml:lang="en">Test QC CA</tsl:Name>
              </tsl:ServiceName>
              <tsl:ServiceStatus>http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/undersupervision</tsl:ServiceStatus>
              <tsl:StatusStartingTime>2016-07-01T00:00:00Z</tsl:StatusStartingTime>
            </tsl:ServiceHistoryInstance>
          </tsl:ServiceHistory>
        </tsl:TSPService>
        <tsl:TSPService>
          <tsl:ServiceInformation>
            <tsl:ServiceTypeIdentifier>http://uri.etsi.org/TrstSvc/Svctype/CA/QC</tsl:ServiceTypeIdentifier>
            <tsl:ServiceName>
              <tsl:Name xml:lang="en">Test Legacy CA</tsl:Name>
            </tsl:ServiceName>
            <tsl:ServiceDigitalIdentity>
              <tsl:DigitalId>
                <tsl:X509SubjectName>CN=Test Legacy CA, O=Test Qualified CA S.A., C=ES</tsl:X509SubjectName>
              </tsl:DigitalId>
              <tsl:DigitalId>
                <tsl:X509SKI>${tsaCert.skiBase64}</tsl:X509SKI>
              </tsl:DigitalId>
            </tsl:ServiceDigitalIdentity>
            <tsl:ServiceStatus>http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/withdrawn</tsl:ServiceStatus>
            <tsl:StatusStartingTime>2019-01-01T00:00:00Z</tsl:StatusStartingTime>
          </tsl:ServiceInformation>
        </tsl:TSPService>
      </tsl:TSPServices>
    </tsl:TrustServiceProvider>
    <tsl:TrustServiceProvider>
      <tsl:TSPInformation>
        <tsl:TSPName>
          <tsl:Name xml:lang="en">Test Timestamping Provider</tsl:Name>
        </tsl:TSPName>
      </tsl:TSPInformation>
      <tsl:TSPServices>
        <tsl:TSPService>
          <tsl:ServiceInformation>
            <tsl:ServiceTypeIdentifier>http://uri.etsi.org/TrstSvc/Svctype/TSA/QTST</tsl:ServiceTypeIdentifier>
            <tsl:ServiceName>
              <tsl:Name xml:lang="en">Test Qualified Timestamping Unit</tsl:Name>
            </tsl:ServiceName>
            <tsl:ServiceDigitalIdentity>
              <tsl:DigitalId>
                <tsl:X509Certificate>${tsaCert.certificateBase64}</tsl:X509Certificate>
              </tsl:DigitalId>
            </tsl:ServiceDigitalIdentity>
            <tsl:ServiceStatus>http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted</tsl:ServiceStatus>
            <tsl:StatusStartingTime>2022-11-20T09:30:00Z</tsl:StatusStartingTime>
          </tsl:ServiceInformation>
        </tsl:TSPService>
      </tsl:TSPServices>
    </tsl:TrustServiceProvider>
  </tsl:TrustServiceProviderList>
</tsl:TrustServiceStatusList>
`
}

function signableTsl(caCert: TestIdentity): string {
  return `<?xml version="1.0" encoding="UTF-8"?>
<tsl:TrustServiceStatusList xmlns:tsl="http://uri.etsi.org/02231/v2#" TSLTag="http://uri.etsi.org/19612/TSLTag" Id="TrustServiceStatusList">
  <tsl:SchemeInformation>
    <tsl:TSLVersionIdentifier>5</tsl:TSLVersionIdentifier>
    <tsl:TSLSequenceNumber>7</tsl:TSLSequenceNumber>
    <tsl:TSLType>http://uri.etsi.org/TrstSvc/TrustedList/TSLType/EUgeneric</tsl:TSLType>
    <tsl:SchemeOperatorName>
      <tsl:Name xml:lang="en">Test Scheme Operator</tsl:Name>
    </tsl:SchemeOperatorName>
    <tsl:ListIssueDateTime>2025-01-15T00:00:00Z</tsl:ListIssueDateTime>
    <tsl:NextUpdate>
      <tsl:dateTime>2025-07-15T00:00:00Z</tsl:dateTime>
    </tsl:NextUpdate>
  </tsl:SchemeInformation>
  <tsl:TrustServiceProviderList>
    <tsl:TrustServiceProvider>
      <tsl:TSPInformation>
        <tsl:TSPName>
          <tsl:Name xml:lang="en">Test Qualified CA S.A.</tsl:Name>
        </tsl:TSPName>
      </tsl:TSPInformation>
      <tsl:TSPServices>
        <tsl:TSPService>
          <tsl:ServiceInformation>
            <tsl:ServiceTypeIdentifier>http://uri.etsi.org/TrstSvc/Svctype/CA/QC</tsl:ServiceTypeIdentifier>
            <tsl:ServiceName>
              <tsl:Name xml:lang="en">Test QC CA</tsl:Name>
            </tsl:ServiceName>
            <tsl:ServiceDigitalIdentity>
              <tsl:DigitalId>
                <tsl:X509Certificate>${caCert.certificateBase64}</tsl:X509Certificate>
              </tsl:DigitalId>
            </tsl:ServiceDigitalIdentity>
            <tsl:ServiceStatus>http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted</tsl:ServiceStatus>
            <tsl:StatusStartingTime>2020-03-01T12:00:00Z</tsl:StatusStartingTime>
          </tsl:ServiceInformation>
        </tsl:TSPService>
      </tsl:TSPServices>
    </tsl:TrustServiceProvider>
  </tsl:TrustServiceProviderList>
</tsl:TrustServiceStatusList>
`
}

async function signTsl(xml: string, signer: TestIdentity): Promise<string> {
  const doc = xadesjs.Parse(xml)
  const signedXml = new xadesjs.SignedXml()
  const signature = await signedXml.Sign({ name: 'RSASSA-PKCS1-v1_5' }, signer.keys.privateKey, doc, {
    references: [{ uri: '', hash: 'SHA-256', transforms: ['enveloped', 'exc-c14n'] }],
    x509: [signer.certificateBase64],
    signingCertificate: signer.certificateBase64,
  })
  doc.documentElement.appendChild(signature.GetXml() as unknown as Node)
  return new XMLSerializer().serializeToString(doc as unknown as XmldomNode)
}

const caCert = await createSelfSigned('CN=Test QC CA, O=Test Qualified CA S.A., C=ES')
const tsaCert = await createSelfSigned('CN=Test Qualified Timestamping Unit, O=Test Timestamping Provider, C=ES')
const signerCert = await createSelfSigned('CN=Test Scheme Operator, O=Test Scheme Operator, C=ES')

const unsignedXml = unsignedTsl(caCert, tsaCert)
const signedXml = await signTsl(signableTsl(caCert), signerCert)

// Sanity check: the generated sample must verify with this package before it
// can become a fixture.
await verifyTrustedListSignature(signedXml)
console.log('Signed sample verifies OK')

const fixtures = `/**
 * Test fixtures — GENERATED by \`scripts/generate-test-fixtures.mts\`, do not
 * edit by hand. The certificates and keys are throwaway test material created
 * by that script; no real trust list or production key is involved.
 */

/** Small standard-style TS 119 612 list (unsigned) for parser tests. */
export const UNSIGNED_TSL_XML = \`${unsignedXml}\`

/** SubjectKeyIdentifier (lowercase hex) of the CA certificate embedded above. */
export const CA_CERT_SKI_HEX = '${caCert.skiHex}'

/** SubjectKeyIdentifier (lowercase hex) advertised by the SKI-only identity. */
export const LEGACY_SKI_HEX = '${tsaCert.skiHex}'

/** Minimal TS 119 612 list carrying a real enveloped XAdES signature. */
export const SIGNED_TSL_XML = \`${signedXml}\`

/** base64 DER of the certificate that signed SIGNED_TSL_XML. */
export const SIGNER_CERT_BASE64 = '${signerCert.certificateBase64}'
`

const outPath = join(dirname(fileURLToPath(import.meta.url)), '..', 'src', '__tests__', 'fixtures.mts')
mkdirSync(dirname(outPath), { recursive: true })
writeFileSync(outPath, fixtures)
console.log(`Wrote ${outPath}`)
