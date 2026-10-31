/**
 * The examples of the pages. Signed examples are made with throwaway keys and certificates
 * issued by the test CA of @owf/eudi-access-certificate, valid until 2036; the keys are not
 * kept. Run `pnpm --filter identity-inspector examples` to make them again.
 */
import { digest, hasher } from '@owf/crypto'
import type { DocumentKind } from '@owf/eudi-inspector'
import { credential, WRP_ENTITLEMENTS, wrprc } from '@owf/eudi-registration-certificate'
import { base64, base64url, base64urlEncode } from '@owf/identity-common'
import { CoseKey, DeviceKey, Issuer, SignatureAlgorithm } from '@owf/mdoc'
import { createHeaderAndPayload, StatusList } from '@owf/token-status-list'
import { createCertificate } from '@owf/x509'
import { Disclosure } from '@sd-jwt/core'
import {
  CA_CERTIFICATE_PEM,
  CA_PRIVATE_JWK,
  OPENSSL_QCP_L_ACCESS_CERTIFICATE_PEM,
} from '../../../packages/eudi-access-certificate/src/__tests__/fixtures.mjs'
import { WRPACProvidersJWT } from '../../../packages/eudi-lote/src/__tests__/fixtures.mjs'
import {
  SIGNED_TSL_XML,
  SIGNER_CERT_BASE64,
  UNSIGNED_TSL_XML,
} from '../../../packages/eudi-tl/src/__tests__/fixtures.mjs'
import { mdocContext } from '../../../packages/mdoc/src/__tests__/context'
import { issuerSignedBytes } from '../../../packages/mdoc/src/__tests__/examples/bdr/issuerSigned'
import { deviceResponse } from '../../../packages/mdoc/src/__tests__/examples/france/deviceResponse'
import type { Example, FeaturedExample } from '../src/example'

const NOW = Math.floor(Date.now() / 1000)
/** Before the test CA expires on 2036-09-25 */
const UNTIL = new Date('2036-09-01T00:00:00Z')
const EXP = Math.floor(UNTIL.getTime() / 1000)

const PID_VCT = 'urn:eudi:pid:1'
const VERIFIER = 'x509_san_dns:verifier.example'
const NONCE = 'n-0S6_WzA2Mj'
const STATUS_LIST_URI = 'https://status.example/lists/1'
// The organizationIdentifier of the access certificate of the test CA
const RELYING_PARTY = 'VATDE-123456789'

interface Key {
  privateKey: CryptoKey
  privateJwk: JsonWebKey
  publicJwk: JsonWebKey
}

async function generateKey(): Promise<Key> {
  const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify'])
  const privateJwk = await crypto.subtle.exportKey('jwk', pair.privateKey)
  const { kty, crv, x, y } = privateJwk
  return { privateKey: pair.privateKey, privateJwk, publicJwk: { kty, crv, x, y } }
}

/** A certificate for the key, issued by the test CA */
async function issueCertificate(publicJwk: JsonWebKey, commonName: string, serialNumber: string) {
  const caKey = await crypto.subtle.importKey('jwk', CA_PRIVATE_JWK, { name: 'ECDSA', namedCurve: 'P-256' }, false, [
    'sign',
  ])
  return createCertificate({
    subject: [
      ['countryName', 'DE'],
      ['organizationName', 'Example'],
      ['commonName', commonName],
    ],
    subjectPublicKey: publicJwk,
    issuerCertificate: CA_CERTIFICATE_PEM,
    serialNumber,
    notBefore: new Date((NOW - 24 * 3600) * 1000),
    notAfter: UNTIL,
    signatureAlgorithm: 'ES256',
    hasher: digest,
    signer: async (tbs) =>
      new Uint8Array(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, caKey, Uint8Array.from(tbs))),
  })
}

async function signJwt(header: Record<string, unknown>, payload: unknown, key: CryptoKey): Promise<string> {
  const input = `${base64urlEncode(JSON.stringify({ alg: 'ES256', ...header }))}.${base64urlEncode(JSON.stringify(payload))}`
  const signature = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, key, new TextEncoder().encode(input))
  return `${input}.${base64url.encode(new Uint8Array(signature))}`
}

const salt = () => base64url.encode(crypto.getRandomValues(new Uint8Array(16)))

// A disclosure of a claim as name and value, or of an array element as value
function disclose(...data: [string, unknown] | [unknown]) {
  const disclosure = new Disclosure([salt(), ...data] as [string, string, unknown] | [string, unknown])
  return {
    encoded: disclosure.encode(),
    digest: disclosure.digestSync({ hasher: (input: string, alg: string) => hasher(input, alg), alg: 'sha-256' }),
  }
}

const pem = (der: Uint8Array) =>
  `-----BEGIN CERTIFICATE-----\n${base64
    .encode(der)
    .match(/.{1,64}/g)
    ?.join('\n')}\n-----END CERTIFICATE-----`

async function sdJwtExamples(): Promise<Example[]> {
  const issuer = await generateKey()
  const holder = await generateKey()
  const certificate = await issueCertificate(issuer.publicJwk, 'Example PID Provider', '1001')
  const header = { typ: 'dc+sd-jwt', x5c: [base64.encode(certificate.der)] }

  const givenName = disclose('given_name', 'Erika')
  const familyName = disclose('family_name', 'Mustermann')
  const birthdate = disclose('birthdate', '1984-01-26')
  const nationality = disclose('DE')
  const claims = {
    vct: PID_VCT,
    iss: 'https://pid-provider.example',
    iat: NOW,
    exp: EXP,
    cnf: { jwk: holder.publicJwk },
    _sd_alg: 'sha-256',
    _sd: [givenName.digest, familyName.digest, birthdate.digest],
    nationalities: [{ '...': nationality.digest }],
  }
  const issued = await signJwt(header, claims, issuer.privateKey)

  // The holder discloses the names, and binds the presentation to the nonce and the verifier
  const presented = `${issued}~${givenName.encoded}~${familyName.encoded}~`
  const keyBinding = await signJwt(
    { typ: 'kb+jwt' },
    { iat: NOW, aud: VERIFIER, nonce: NONCE, sd_hash: base64url.encode(hasher(presented, 'sha-256')) },
    holder.privateKey
  )
  const presentation = `${presented}${keyBinding}`

  // A disclosure the issuer did not make, so no digest references it
  const added = disclose('age_over_18', true)
  const unreferenced = `${issued}~${givenName.encoded}~${added.encoded}~`

  return [
    {
      id: 'pid-presentation',
      title: 'PID presentation',
      description:
        'An SD-JWT VC of a PID that discloses the names, with a Key Binding JWT for the expected verifier and nonce. The issuer signature is checked up to the test CA, given as trust anchor.',
      values: { doc: presentation, key: CA_CERTIFICATE_PEM, nonce: NONCE, aud: VERIFIER },
      expect: { findings: [], signatures: ['valid', 'valid'] },
    },
    {
      id: 'other-verifier',
      title: 'Presented to another verifier',
      description:
        'The same presentation, checked by a verifier it was not made for: the aud of the Key Binding JWT is not this verifier.',
      values: { doc: presentation, key: CA_CERTIFICATE_PEM, nonce: NONCE, aud: 'x509_san_dns:other-verifier.example' },
      expect: { findings: ['kb_aud_mismatch'], signatures: ['valid', 'valid'] },
    },
    {
      id: 'unreferenced-disclosure',
      title: 'Disclosure the issuer did not make',
      description:
        'An SD-JWT VC with an added disclosure of age_over_18 that no digest references. Without a trust anchor, the signature is verified with the x5c certificate only.',
      values: { doc: unreferenced },
      expect: { findings: ['unreferenced_disclosure'], signatures: ['valid'] },
    },
  ]
}

function registration(identifier: string, credentials: ReturnType<ReturnType<typeof credential>['build']>[]) {
  let builder = wrprc()
    .name('Example Shop')
    .legalName('Example Shop GmbH')
    .identifier(identifier)
    .country('DE')
    .registryUri('https://registrar.example/wrp')
    .addEntitlement(WRP_ENTITLEMENTS.SERVICE_PROVIDER)
    .addPurpose('Age verification at checkout')
    .issuedAt(NOW)
  for (const entry of credentials) builder = builder.addCredential(entry)
  return builder.build()
}

async function registrationExamples(): Promise<Example[]> {
  const registrar = await generateKey()
  const certificate = await issueCertificate(registrar.publicJwk, 'Example Registrar', '1002')
  const header = { typ: 'rc-wrp+jwt', x5c: [base64.encode(certificate.der)], iat: NOW }
  const credentials = [credential().sdJwtMeta([PID_VCT]).addPathClaim('given_name').addPathClaim('family_name').build()]
  const own = await signJwt(header, registration(RELYING_PARTY, credentials), registrar.privateKey)
  const other = await signJwt(header, registration('VATDE-987654321', credentials), registrar.privateKey)

  return [
    {
      id: 'for-the-relying-party',
      title: 'For its relying party',
      description:
        'A registration certificate of Example Shop, checked with the access certificate of the relying party, which has the same subject. The signature is checked up to the test CA.',
      values: { doc: own, access: OPENSSL_QCP_L_ACCESS_CERTIFICATE_PEM, key: CA_CERTIFICATE_PEM },
      expect: { findings: [], signatures: ['valid'] },
    },
    {
      id: 'for-another-relying-party',
      title: 'For another relying party',
      description:
        'A registration certificate for VATDE-987654321, presented with the access certificate of VATDE-123456789.',
      values: { doc: other, access: OPENSSL_QCP_L_ACCESS_CERTIFICATE_PEM, key: CA_CERTIFICATE_PEM },
      expect: { findings: ['access_certificate_identity_mismatch'], signatures: ['valid'] },
    },
  ]
}

async function overAskingExamples(): Promise<Example[]> {
  const registrar = await generateKey()
  const certificate = await issueCertificate(registrar.publicJwk, 'Example Registrar', '1003')
  const registered = await signJwt(
    { typ: 'rc-wrp+jwt', x5c: [base64.encode(certificate.der)], iat: NOW },
    registration(RELYING_PARTY, [
      credential().sdJwtMeta([PID_VCT]).addPathClaim('given_name').addPathClaim('family_name').build(),
    ]),
    registrar.privateKey
  )
  const request = (claims: string[][], credentials: unknown[] = []) =>
    JSON.stringify(
      {
        response_type: 'vp_token',
        client_id: VERIFIER,
        nonce: NONCE,
        dcql_query: {
          credentials: [
            {
              id: 'pid',
              format: 'dc+sd-jwt',
              meta: { vct_values: [PID_VCT] },
              claims: claims.map((path) => ({ path })),
            },
            ...credentials,
          ],
        },
        verifier_info: [{ format: 'jwt', data: registered }],
      },
      null,
      2
    )

  return [
    {
      id: 'within-the-registration',
      title: 'Within the registration',
      description:
        'An authorization request for the names of a PID, which the registration certificate in its verifier_info registers.',
      values: { request: request([['given_name'], ['family_name']]) },
      expect: { findings: [], signatures: [] },
    },
    {
      id: 'asks-for-more',
      title: 'Asks for more',
      description:
        'The same relying party also asks for the birthdate of the PID and for an mDL, neither of which it registered.',
      values: {
        request: request(
          [['given_name'], ['family_name'], ['birthdate']],
          [
            {
              id: 'mdl',
              format: 'mso_mdoc',
              meta: { doctype_value: 'org.iso.18013.5.1.mDL' },
              claims: [{ path: ['org.iso.18013.5.1', 'driving_privileges'] }],
            },
          ]
        ),
      },
      expect: { findings: ['claim_not_registered', 'credential_not_registered'], signatures: [] },
    },
  ]
}

async function statusListExamples(): Promise<Example[]> {
  const issuer = await generateKey()
  const certificate = await issueCertificate(issuer.publicJwk, 'Example Status Issuer', '1004')
  // 0 valid, 1 invalid, 2 suspended
  const statuses = [0, 0, 1, 0, 2, 0, 0, 0, 1, 0, 0, 0, 0, 2, 0, 0]
  const { header, payload } = createHeaderAndPayload(
    new StatusList(statuses, 2),
    { sub: STATUS_LIST_URI, iat: NOW, exp: EXP, ttl: 43_200 },
    { alg: 'ES256', typ: 'statuslist+jwt' }
  )
  const jwt = await signJwt({ ...header, x5c: [base64.encode(certificate.der)] }, payload, issuer.privateKey)

  return [
    {
      id: 'revoked-and-suspended',
      title: 'Revoked and suspended tokens',
      description:
        'A status list of 2 bits per token with revoked and suspended entries, looked up at index 2, for the uri of its reference. The signature is checked up to the test CA.',
      values: { doc: jwt, uri: STATUS_LIST_URI, key: CA_CERTIFICATE_PEM, lookup: '2' },
      expect: { findings: [], signatures: ['valid'] },
    },
    {
      id: 'other-uri',
      title: 'Referenced by another uri',
      description: 'The same status list, for a token whose status claim points to another uri.',
      values: { doc: jwt, uri: 'https://status.example/lists/2', key: CA_CERTIFICATE_PEM, lookup: '4' },
      expect: { findings: ['subject_mismatch'], signatures: ['valid'] },
    },
  ]
}

async function mdocExamples(): Promise<Example[]> {
  const issuer = await generateKey()
  const device = await generateKey()
  const certificate = await issueCertificate(issuer.publicJwk, 'Example mDL Issuer', '1005')
  const mdl = new Issuer('org.iso.18013.5.1.mDL', mdocContext)
  mdl.addIssuerNamespace('org.iso.18013.5.1', {
    family_name: 'Mustermann',
    given_name: 'Erika',
    issuing_country: 'DE',
    issuing_authority: 'Example Authority',
    document_number: 'T22000129',
  })
  const issuerSigned = await mdl.sign({
    signingKey: CoseKey.fromJwk(issuer.privateJwk as Record<string, unknown>),
    certificates: [certificate.der],
    algorithm: SignatureAlgorithm.ES256,
    digestAlgorithm: 'SHA-256',
    deviceKeyInfo: { deviceKey: DeviceKey.fromJwk(device.publicJwk as Record<string, unknown>) },
    validityInfo: { signed: new Date(NOW * 1000), validFrom: new Date(NOW * 1000), validUntil: UNTIL },
  })

  return [
    {
      id: 'mdl',
      title: 'mDL',
      description:
        'An mDL IssuerSigned with five elements, each matching its digest in the Mobile Security Object, signed by a certificate of the test CA.',
      values: { doc: base64url.encode(issuerSigned.encode()) },
      expect: { findings: [], signatures: [] },
    },
    {
      id: 'bdr-mdl',
      title: 'BDR test mDL',
      description:
        'The test mDL of the Bundesdruckerei with 18 elements, whose digests all match, but which expired in February 2026.',
      values: { doc: base64url.encode(issuerSignedBytes) },
      expect: { findings: ['expired'], signatures: [] },
    },
    {
      id: 'device-response',
      title: 'DeviceResponse from 2020',
      description: 'A DeviceResponse of the French test mDL, which expired long ago.',
      values: { doc: base64url.encode(deviceResponse) },
      expect: { findings: ['expired'], signatures: [] },
    },
  ]
}

function trustedListExamples(): Example[] {
  return [
    {
      id: 'eu-lotl',
      title: 'EU List of Trusted Lists',
      description:
        'The live EU LOTL, fetched from ec.europa.eu and verified against the signing certificates shipped with @owf/eudi-tl, with the national lists it points to.',
      values: { url: 'https://ec.europa.eu/tools/lotl/eu-lotl.xml' },
    },
    {
      id: 'signed-list',
      title: 'Signed by its scheme operator',
      description: 'A signed test list, with the certificate of its scheme operator given as the signer to expect.',
      values: { doc: SIGNED_TSL_XML, signers: pem(base64.decode(SIGNER_CERT_BASE64)) },
      expect: { findings: [], signatures: ['valid'] },
    },
    {
      id: 'unsigned-list',
      title: 'Not signed',
      description:
        'A test list of Spain with two trust service providers and pointers to two other lists, but no signature.',
      values: { doc: UNSIGNED_TSL_XML },
      expect: { findings: [], signatures: ['invalid'] },
    },
  ]
}

function loteExamples(): Example[] {
  const [, payload] = WRPACProvidersJWT.split('.')
  const document = JSON.parse(new TextDecoder().decode(base64url.decode(payload)))
  document.LoTE.ListAndSchemeInformation.StatusDeterminationApproach = 'http://example.com/unknown'
  return [
    {
      id: 'wrpac-providers',
      title: 'Access certificate providers',
      description:
        'A signed test list of the providers of access certificates, checked against the EUWRPACProvidersList profile. Without a trust anchor, the signature is verified with the x5c certificate only.',
      values: { doc: WRPACProvidersJWT },
      expect: { findings: [], signatures: ['valid'] },
    },
    {
      id: 'unknown-approach',
      title: 'Unknown status approach',
      description: 'The same list as unsigned JSON, with a StatusDeterminationApproach the profile does not allow.',
      values: { doc: JSON.stringify(document, null, 2) },
      expect: { findings: ['invalid_value'], signatures: [] },
    },
  ]
}

function accessCertificateExamples(): Example[] {
  return [
    {
      id: 'access-certificate',
      title: 'Access certificate',
      description:
        'An access certificate of a relying party, verified with the certificate of the test CA that issued it.',
      values: { doc: OPENSSL_QCP_L_ACCESS_CERTIFICATE_PEM, issuer: CA_CERTIFICATE_PEM },
      expect: { findings: [], signatures: ['valid'] },
    },
    {
      id: 'ca-certificate',
      title: 'A CA certificate',
      description: 'The certificate of the CA, checked as if it were an access certificate.',
      values: { doc: CA_CERTIFICATE_PEM },
      expect: {
        findings: [
          'CA_CERTIFICATE',
          'MISSING_CONTACT',
          'MISSING_CPS_URI',
          'MISSING_DIGITAL_SIGNATURE_KEY_USAGE',
          'MISSING_POLICY',
        ],
        signatures: ['unverified'],
      },
    },
  ]
}

/** The examples of each page, and those the start page offers */
export async function generateExamples(): Promise<{
  pages: Record<DocumentKind, Example[]>
  featured: FeaturedExample[]
}> {
  const pages: Record<DocumentKind, Example[]> = {
    'trusted-list': trustedListExamples(),
    lote: loteExamples(),
    'registration-certificate': await registrationExamples(),
    'access-certificate': accessCertificateExamples(),
    'status-list': await statusListExamples(),
    'sd-jwt': await sdJwtExamples(),
    mdoc: await mdocExamples(),
    'over-asking': await overAskingExamples(),
  }
  const pick = (page: DocumentKind, id: string): FeaturedExample => {
    const example = pages[page].find((entry) => entry.id === id)
    if (!example) throw new Error(`There is no example ${id} of ${page}`)
    return { page, id, title: example.title }
  }
  return {
    pages,
    featured: [
      pick('sd-jwt', 'pid-presentation'),
      pick('over-asking', 'asks-for-more'),
      pick('trusted-list', 'eu-lotl'),
      pick('status-list', 'revoked-and-suspended'),
      pick('registration-certificate', 'for-another-relying-party'),
      pick('mdoc', 'mdl'),
    ],
  }
}
