import { hasher } from '@owf/crypto'
import { base64url, base64urlEncode } from '@owf/identity-common'
import { Disclosure } from '@sd-jwt/core'
import { describe, expect, it } from 'vitest'
import { type Inspection, inspect } from '../inspect'
import { SD_JWT_CODES as CODES, inspectSdJwt } from '../sd-jwt'
import { generateKey, signJwt } from './keys.mjs'

const NOW = Math.floor(Date.now() / 1000)
const hasherSync = (data: string, alg: string) => hasher(data, alg)

const jws = (header: Record<string, unknown>, payload: unknown) =>
  `${base64urlEncode(JSON.stringify(header))}.${base64urlEncode(JSON.stringify(payload))}.c2ln`

function disclose(...data: [string, string, unknown] | [string, unknown]) {
  const disclosure = new Disclosure(data)
  return { encoded: disclosure.encode(), digest: disclosure.digestSync({ hasher: hasherSync, alg: 'sha-256' }) }
}

const givenName = disclose('salt-1', 'given_name', 'Erika')
const familyName = disclose('salt-2', 'family_name', 'Mustermann')
const nationality = disclose('salt-3', 'DE')

function sdJwt({
  header = { alg: 'ES256', typ: 'dc+sd-jwt' },
  claims = {},
  disclosures = [givenName, familyName, nationality],
}: {
  header?: Record<string, unknown>
  claims?: Record<string, unknown>
  disclosures?: { encoded: string }[]
} = {}) {
  const payload = {
    vct: 'urn:eudi:pid:1',
    iss: 'https://issuer.example',
    iat: NOW - 60,
    exp: NOW + 3600,
    cnf: { jwk: { kty: 'EC', crv: 'P-256', x: 'x', y: 'y' } },
    _sd_alg: 'sha-256',
    _sd: [givenName.digest, familyName.digest],
    nationalities: [{ '...': nationality.digest }],
    ...claims,
  }
  return `${jws(header, payload)}~${disclosures.map((disclosure) => `${disclosure.encoded}~`).join('')}`
}

function withKeyBinding(presentation: string, header: Record<string, unknown> = { alg: 'ES256', typ: 'kb+jwt' }) {
  const sdHash = base64url.encode(hasher(presentation, 'sha-256'))
  return (claims: Record<string, unknown> = {}) =>
    `${presentation}${jws(header, { iat: NOW, aud: 'https://verifier.example', nonce: 'n-0S6', sd_hash: sdHash, ...claims })}`
}

const codesAndPaths = (input: string) =>
  inspect(input).findings.map(({ severity, code, path }) => ({ severity, code, path }))

describe('SD-JWT inspection', () => {
  it('resolves the claims and shows which claim each disclosure discloses', () => {
    const inspection = inspect(sdJwt())

    expect(inspection).toMatchObject({ kind: 'sd-jwt', title: 'SD-JWT VC', findings: [] })
    expect(inspection.value).toMatchObject({
      claims: { given_name: 'Erika', family_name: 'Mustermann', nationalities: ['DE'] },
      disclosures: [
        { digest: givenName.digest, discloses: 'given_name', name: 'given_name', value: 'Erika' },
        { digest: familyName.digest, discloses: 'family_name' },
        { digest: nationality.digest, value: 'DE' },
      ],
    })
    expect(inspection.facts).toEqual([
      ['Type (vct)', 'urn:eudi:pid:1'],
      ['Disclosures', '3, hashed with sha-256'],
      ['Key Binding', 'None'],
    ])
  })

  it('reports a disclosure that no digest references', () => {
    const unreferenced = disclose('salt-4', 'birthdate', '1984-01-26')
    expect(codesAndPaths(sdJwt({ disclosures: [givenName, unreferenced] }))).toEqual([
      { severity: 'error', code: CODES.UNREFERENCED_DISCLOSURE, path: ['disclosures', 1] },
    ])
  })

  it('reports a disclosure presented twice and one that does not decode', () => {
    expect(codesAndPaths(sdJwt({ disclosures: [givenName, givenName, { encoded: 'bm90IGpzb24' }] }))).toEqual([
      { severity: 'error', code: CODES.INVALID_DISCLOSURE, path: ['disclosures', 2] },
      { severity: 'error', code: CODES.DUPLICATE_DISCLOSURE, path: ['disclosures', 1] },
    ])
  })

  it('checks the claims of an SD-JWT VC', () => {
    const vct = disclose('salt-5', 'vct', 'urn:eudi:pid:1')
    const protectedClaim = sdJwt({ claims: { vct: undefined, _sd: [vct.digest] }, disclosures: [vct] })
    expect(codesAndPaths(protectedClaim)).toEqual([
      { severity: 'error', code: CODES.PROTECTED_CLAIM_DISCLOSED, path: ['claims', 'vct'] },
    ])

    expect(
      codesAndPaths(sdJwt({ header: { alg: 'none', typ: 'vc+sd-jwt' }, claims: { exp: NOW - 3600, status: {} } }))
    ).toEqual([
      { severity: 'error', code: CODES.INVALID_ALG, path: ['header', 'alg'] },
      { severity: 'warning', code: CODES.INVALID_TYP, path: ['header', 'typ'] },
      { severity: 'error', code: CODES.INVALID_STATUS, path: ['claims', 'status'] },
      { severity: 'error', code: CODES.EXPIRED, path: ['claims', 'exp'] },
    ])
  })

  it('checks the Key Binding JWT and its sd_hash', () => {
    const presentation = withKeyBinding(sdJwt())
    const inspection = inspect(presentation())
    expect(inspection).toMatchObject({ title: 'SD-JWT VC presentation', findings: [] })
    expect(inspection.value).toMatchObject({ key_binding: { payload: { nonce: 'n-0S6' } } })

    expect(codesAndPaths(presentation({ sd_hash: 'wrong', nonce: undefined }))).toEqual([
      { severity: 'error', code: CODES.MISSING_KB_CLAIM, path: ['key_binding', 'payload', 'nonce'] },
      { severity: 'error', code: CODES.SD_HASH_MISMATCH, path: ['key_binding', 'payload', 'sd_hash'] },
    ])
    expect(codesAndPaths(withKeyBinding(sdJwt(), { alg: 'ES256', typ: 'JWT' })())).toEqual([
      { severity: 'error', code: CODES.INVALID_KB_TYP, path: ['key_binding', 'header', 'typ'] },
    ])
    expect(codesAndPaths(withKeyBinding(sdJwt({ claims: { cnf: undefined } }))())).toEqual([
      { severity: 'error', code: CODES.MISSING_CNF, path: ['claims'] },
    ])
  })

  it('reports an SD-JWT VC without the ~ separator', () => {
    const issuerJwt = sdJwt().split('~')[0]
    expect(codesAndPaths(issuerJwt)).toContainEqual({ severity: 'error', code: CODES.MISSING_SEPARATOR, path: [] })
  })
})

describe('SD-JWT verification', () => {
  async function presentation(kbClaims: Record<string, unknown> = {}) {
    const issuer = await generateKey()
    const holder = await generateKey()
    const issued = `${await signJwt(
      { typ: 'dc+sd-jwt' },
      {
        vct: 'urn:eudi:pid:1',
        iss: 'https://issuer.example',
        iat: NOW - 60,
        cnf: { jwk: holder.publicJwk },
        _sd_alg: 'sha-256',
        _sd: [givenName.digest],
      },
      issuer.privateKey
    )}~${givenName.encoded}~`
    const sdHash = base64url.encode(hasher(issued, 'sha-256'))
    const keyBinding = await signJwt(
      { typ: 'kb+jwt' },
      { iat: NOW, aud: 'https://verifier.example', nonce: 'n-0S6', sd_hash: sdHash, ...kbClaims },
      holder.privateKey
    )
    return { text: `${issued}${keyBinding}`, issuer, holder }
  }

  const verifyAll = (inspection: Inspection) =>
    Promise.all((inspection.signatures ?? []).map(async ({ label, verify }) => ({ label, ...(await verify()) })))

  it('verifies the issuer signature with the given key, and the Key Binding JWT with the key in cnf', async () => {
    const { text, issuer } = await presentation()
    const inspection = inspectSdJwt(text, {
      key: JSON.stringify(issuer.publicJwk),
      nonce: 'n-0S6',
      aud: 'https://verifier.example',
    })
    expect(inspection.findings).toEqual([])
    expect(await verifyAll(inspection)).toEqual([
      { label: 'Issuer signature', status: 'valid', message: 'Valid, signed with the key you gave (JWK).' },
      {
        label: 'Key Binding JWT',
        status: 'valid',
        message: 'Valid, signed with the cnf key of the SD-JWT (JWK).',
      },
    ])
  })

  it('reports another nonce and aud, and a Key Binding JWT not signed with the key in cnf', async () => {
    const { text, holder } = await presentation({ nonce: 'old', aud: 'https://other.example' })
    const inspection = inspectSdJwt(text, { nonce: 'n-0S6', aud: 'https://verifier.example' })
    expect(inspection.findings.map(({ code, path }) => ({ code, path }))).toEqual([
      { code: CODES.KB_NONCE_MISMATCH, path: ['key_binding', 'payload', 'nonce'] },
      { code: CODES.KB_AUD_MISMATCH, path: ['key_binding', 'payload', 'aud'] },
    ])

    // Without a key or an x5c, the issuer signature cannot be verified
    const [issuerSignature, keyBinding] = await verifyAll(inspection)
    expect(issuerSignature.status).toBe('unverified')
    expect(keyBinding.status).toBe('valid')

    const tampered = `${text.slice(0, text.lastIndexOf('~') + 1)}${await signJwt({ typ: 'kb+jwt' }, {}, (await generateKey()).privateKey)}`
    const [, forged] = await verifyAll(inspectSdJwt(tampered, { key: JSON.stringify(holder.publicJwk) }))
    expect(forged).toMatchObject({ label: 'Key Binding JWT', status: 'invalid' })
  })
})
