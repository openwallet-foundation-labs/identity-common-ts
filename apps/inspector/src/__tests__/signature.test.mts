import { base64 } from '@owf/identity-common'
import { describe, expect, it } from 'vitest'
import { OPENSSL_QCP_L_ACCESS_CERTIFICATE_PEM } from '../../../../packages/eudi-access-certificate/src/__tests__/fixtures.mjs'
import { InspectionError } from '../inspection'
import { parseKeys, verifyJwsSignature } from '../signature'
import { CA_CERTIFICATE_PEM, generateKey, issueCertificate, signJwt } from './keys.mjs'

const decodeHeader = (jws: string) => JSON.parse(atob(jws.split('.')[0].replace(/-/g, '+').replace(/_/g, '/')))
const given = (text: string) => ({ keys: parseKeys(text), source: 'the key you gave' })

describe('signature verification', () => {
  it('verifies a JWS with a JWK or a JWK Set, and rejects another key', async () => {
    const signer = await generateKey()
    const other = await generateKey()
    const jws = await signJwt({ typ: 'JWT', kid: 'k1' }, { sub: 'x' }, signer.privateKey)
    const header = decodeHeader(jws)

    await expect(verifyJwsSignature(jws, header, given(JSON.stringify(signer.publicJwk)))).resolves.toMatchObject({
      status: 'valid',
    })
    const set = JSON.stringify({ keys: [other.publicJwk, { ...signer.publicJwk, kid: 'k1' }] })
    await expect(verifyJwsSignature(jws, header, given(set))).resolves.toEqual({
      status: 'valid',
      message: 'Valid, signed with the key you gave (JWK k1).',
    })
    await expect(verifyJwsSignature(jws, header, given(JSON.stringify(other.publicJwk)))).resolves.toMatchObject({
      status: 'invalid',
    })
  })

  it('says which key is missing when there is neither a given key nor an x5c', async () => {
    const { privateKey } = await generateKey()
    const jws = await signJwt({ kid: 'issuer-key-1' }, {}, privateKey)
    await expect(verifyJwsSignature(jws, decodeHeader(jws))).resolves.toEqual({
      status: 'unverified',
      message: 'Not verified: the header has no x5c, so give the key with the kid issuer-key-1 of the signer.',
    })
    await expect(verifyJwsSignature(jws, { alg: 'none' })).resolves.toMatchObject({ status: 'invalid' })
  })

  it('verifies with the x5c of the header, and its chain with a certificate of a trust anchor', async () => {
    const signer = await generateKey()
    const certificate = await issueCertificate(signer.publicJwk)
    const jws = await signJwt({ x5c: [base64.encode(certificate.der)] }, { sub: 'x' }, signer.privateKey)
    const header = decodeHeader(jws)

    const integrity = await verifyJwsSignature(jws, header)
    expect(integrity.status).toBe('valid')
    expect(integrity.message).toContain('This proves integrity only')

    await expect(verifyJwsSignature(jws, header, given(CA_CERTIFICATE_PEM))).resolves.toEqual({
      status: 'valid',
      message:
        'Valid, signed with the x5c certificate Example Issuer, and its chain leads to the certificate you gave, Example WRP Access CA.',
    })
    // A certificate that did not issue it
    await expect(verifyJwsSignature(jws, header, given(OPENSSL_QCP_L_ACCESS_CERTIFICATE_PEM))).resolves.toMatchObject({
      status: 'invalid',
      message: expect.stringContaining('does not lead to'),
    })

    // Signed with another key than the one of the x5c certificate
    const other = await generateKey()
    const forged = await signJwt({ x5c: [base64.encode(certificate.der)] }, { sub: 'x' }, other.privateKey)
    await expect(verifyJwsSignature(forged, decodeHeader(forged))).resolves.toMatchObject({ status: 'invalid' })
  })

  it('reads keys as JWK, JWK Set, PEM and base64, and rejects anything else', async () => {
    const { publicJwk } = await generateKey()
    expect(parseKeys(JSON.stringify(publicJwk))).toHaveLength(1)
    expect(parseKeys(`${CA_CERTIFICATE_PEM}\n${OPENSSL_QCP_L_ACCESS_CERTIFICATE_PEM}`)).toHaveLength(2)
    const der = CA_CERTIFICATE_PEM.replace(/-----[^-]+-----/g, '').replace(/\s+/g, '')
    expect(parseKeys(der)[0].description).toBe('certificate Example WRP Access CA')
    expect(() => parseKeys('{"foo": 1}')).toThrow(InspectionError)
    expect(() => parseKeys('not a key!')).toThrow(InspectionError)
  })
})
