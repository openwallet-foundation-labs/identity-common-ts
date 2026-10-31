import { mkdtemp, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { credential, WRP_ENTITLEMENTS, wrprc } from '@owf/eudi-registration-certificate'
import { base64url, base64urlEncode } from '@owf/identity-common'
import { createHeaderAndPayload, StatusList } from '@owf/token-status-list'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { issuerSignedBytes } from '../../../mdoc/src/__tests__/examples/bdr/issuerSigned'
import { type CliEnvironment, EXIT, run, WEB_URL } from '../cli-run'
import { fromFragment } from '../share'
import { generateKey, signJwt } from './keys.mjs'

const NOW = Math.floor(Date.now() / 1000)

const fakeJws = (header: Record<string, unknown>, payload: unknown) =>
  `${base64urlEncode(JSON.stringify(header))}.${base64urlEncode(JSON.stringify(payload))}.c2ln`

async function cli(args: string[], stdin: Uint8Array = new Uint8Array()) {
  const stdout: string[] = []
  const stderr: string[] = []
  const environment: CliEnvironment = {
    stdout: (text) => stdout.push(text),
    stderr: (text) => stderr.push(text),
    readStdin: async () => stdin,
    fetch: async () => {
      throw new Error('offline')
    },
    crypto,
    color: false,
    version: '1.2.3',
  }
  const status = await run(args, environment)
  return { status, stdout: stdout.join('\n'), stderr: stderr.join('\n') }
}

const statusList = () => {
  const { header, payload } = createHeaderAndPayload(
    new StatusList([0, 1, 0, 0, 0, 0, 0, 0], 1),
    { sub: 'https://example.com/statuslists/1', iat: NOW, ttl: 300 },
    { alg: 'ES256', typ: 'statuslist+jwt' }
  )
  return fakeJws(header, payload)
}

describe('eudi-inspect', () => {
  let directory: string
  beforeAll(async () => {
    directory = await mkdtemp(join(tmpdir(), 'eudi-inspect-'))
  })
  afterAll(async () => {
    await rm(directory, { recursive: true, force: true })
  })

  it('shows its help and version', async () => {
    expect(await cli(['--help'])).toMatchObject({ status: EXIT.OK, stdout: expect.stringContaining('Usage:') })
    expect(await cli(['-v'])).toMatchObject({ status: EXIT.OK, stdout: '1.2.3' })
    expect(await cli([])).toMatchObject({ status: EXIT.UNREADABLE, stderr: expect.stringContaining('Give a document') })
    expect(await cli(['--format', 'pdf', 'x'])).toMatchObject({
      status: EXIT.UNREADABLE,
      stderr: expect.stringContaining('Unknown format pdf'),
    })
  })

  it('verifies an SD-JWT with a key from a file, and fails on a Key Binding JWT for another verifier', async () => {
    const issuer = await generateKey()
    const holder = await generateKey()
    const issued = `${await signJwt(
      { typ: 'dc+sd-jwt' },
      { vct: 'urn:eudi:pid:1', iss: 'https://issuer.example', iat: NOW, cnf: { jwk: holder.publicJwk } },
      issuer.privateKey
    )}~`
    const { hasher } = await import('@owf/crypto')
    const keyBinding = await signJwt(
      { typ: 'kb+jwt' },
      { iat: NOW, aud: 'https://other.example', nonce: 'n-0S6', sd_hash: base64url.encode(hasher(issued, 'sha-256')) },
      holder.privateKey
    )
    const keyFile = join(directory, 'issuer.jwk')
    await writeFile(keyFile, JSON.stringify(issuer.publicJwk))

    const args = [`${issued}${keyBinding}`, '--key', keyFile, '--nonce', 'n-0S6', '--aud', 'https://verifier.example']
    const text = await cli(args)
    expect(text.status).toBe(EXIT.FAILED)
    expect(text.stdout).toContain('SD-JWT VC presentation  1 error')
    expect(text.stdout).toContain('Valid, signed with the key you gave (JWK).')
    expect(text.stdout).toContain('error    kb_aud_mismatch at key_binding.payload.aud (RFC 9901 Section 7.3)')

    const json = await cli([...args, '--json'])
    expect(JSON.parse(json.stdout)).toMatchObject({
      source: 'the argument',
      kind: 'sd-jwt',
      valid: false,
      findings: [{ code: 'kb_aud_mismatch', path: ['key_binding', 'payload', 'aud'] }],
      signatures: [
        { label: 'Issuer signature', status: 'valid' },
        { label: 'Key Binding JWT', status: 'valid' },
      ],
      value: { claims: { vct: 'urn:eudi:pid:1' } },
    })
  })

  it('reads a document from a file, looks up a status, and fails on warnings when strict', async () => {
    const file = join(directory, 'status-list.jwt')
    await writeFile(file, statusList())

    const result = await cli([file, '--index', '1'])
    // exp is missing, which is a warning, and the signature has no key to verify it with
    expect(result.status).toBe(EXIT.OK)
    expect(result.stdout).toContain('Token Status List (JWT)  1 warning')
    expect(result.stdout).toMatch(/Status at 1 +Invalid \(0x01\)/)
    expect(result.stdout).toContain('warning  missing_expiration_time at payload.exp')

    expect((await cli([file, '--strict'])).status).toBe(EXIT.FAILED)
  })

  it('reads standard input, and reports what it cannot read', async () => {
    const mdoc = await cli(['-', '--json'], issuerSignedBytes)
    expect(JSON.parse(mdoc.stdout)).toMatchObject({ source: 'standard input', kind: 'mdoc' })

    const missing = await cli(['no-such-file.jwt'])
    expect(missing.status).toBe(EXIT.UNREADABLE)
    expect(missing.stderr).toContain('There is no file named no-such-file.jwt either.')

    const unreachable = await cli(['https://example.com/list.xml'])
    expect(unreachable).toMatchObject({ status: EXIT.UNREADABLE, stderr: expect.stringContaining('offline') })

    // Several documents: the exit status is the worst of them
    expect((await cli([statusList(), 'no-such-file.jwt'])).status).toBe(EXIT.UNREADABLE)
  })

  it('prints a link that opens the document in the web page', async () => {
    const document = statusList()
    const { stdout } = await cli([
      document,
      '--uri',
      'https://example.com/statuslists/1',
      '--index',
      '1',
      '--link',
      '--json',
    ])
    const { link } = JSON.parse(stdout)
    expect(link.startsWith(`${WEB_URL}status-list/#`)).toBe(true)
    const values = await fromFragment(new URL(link).hash, new Set(['doc']))
    expect(Object.fromEntries(values)).toEqual({ doc: document, uri: 'https://example.com/statuslists/1', lookup: '1' })
  })

  it('checks a request for over-asking', async () => {
    const registration = fakeJws(
      { typ: 'rc-wrp+jwt', alg: 'ES256', iat: 1_700_000_000 },
      wrprc()
        .name('Example Shop')
        .legalName('Example Shop GmbH')
        .identifier('VATDE-123456789')
        .country('DE')
        .registryUri('https://registry.test/wrp')
        .addEntitlement(WRP_ENTITLEMENTS.SERVICE_PROVIDER)
        .addPurpose('Age verification')
        .addCredential(credential().sdJwtMeta(['urn:eudi:pid:1']).addPathClaim('given_name').build())
        .issuedAt(1_700_000_000)
        .build()
    )
    const request = JSON.stringify({
      credentials: [
        {
          id: 'pid',
          format: 'dc+sd-jwt',
          meta: { vct_values: ['urn:eudi:pid:1'] },
          claims: [{ path: ['given_name'] }, { path: ['birthdate'] }],
        },
      ],
    })
    const result = await cli(['over-asking', request, '--registration', registration, '--json'])
    expect(result.status).toBe(EXIT.FAILED)
    expect(JSON.parse(result.stdout).findings).toContainEqual(
      expect.objectContaining({ code: 'claim_not_registered', path: ['dcql_query', 'credentials', 0, 'claims', 1] })
    )
  })
})
