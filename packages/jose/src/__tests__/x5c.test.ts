import { base64, base64url, concatBytes, stringToBytes } from '@owf/identity-common'
import { describe, expect, it } from 'vitest'
import { JoseValidationError } from '../error'
import * as entryPoint from '../index'
import { zJweHeader } from '../jwe/z-jwe'
import { zJwk, zJwkSet } from '../jwk/z-jwk'
import { zX5c, zX5cCertificate } from '../jwk/z-x5c'
import { parseJws } from '../jws/parse-jws'
import { zJwsProtectedHeader } from '../jws/z-jws'
import { decodeJwtHeader } from '../jwt/decode-jwt'
import { signJwt } from '../jwt/sign-jwt'
import { verifyJwt } from '../jwt/verify-jwt'
import { certificateChain, emptySequence, leafCertificate, rfc7517Certificate, rootCertificate } from './certificates'
import { createEs256Context, unsignedCompactJws } from './context'

/**
 * RFC 7515 section 4.1.6 and RFC 7517 section 4.7: `x5c` is a chain of one or more certificates, each
 * the standard base64 (RFC 4648 section 4, not base64url) of a DER encoded certificate. That much is
 * checked when a header or a JWK is parsed; whether the certificates are valid and trusted is for the
 * verification callback.
 */

/** Matches a thrown error by its class and a part of its message. */
const joseError = (type: { name: string }, message: string) =>
  expect.objectContaining({ name: type.name, message: expect.stringContaining(message) })

const base64Problem = (reason: string) =>
  `Expected a certificate in standard base64 (RFC 4648 section 4), but ${reason}`
const derProblem = (reason: string) =>
  `Expected a DER encoded certificate, but the decoded bytes are not a single DER SEQUENCE: ${reason}`

const leafBytes = base64.decode(leafCertificate)
const rootBytes = base64.decode(rootCertificate)
const encodeBytes = (...bytes: number[]) => base64.encode(new Uint8Array(bytes))

/** An entry of an `x5c` that is rejected, and the message it is rejected with. */
interface RejectedCertificate {
  description: string
  certificate: string
  message: string
}

const rejectedCertificates: RejectedCertificate[] = [
  {
    description: `a certificate in base64url, with '-' where base64 has '+'`,
    certificate: leafCertificate.replace(/\+/g, '-'),
    message: base64Problem(`it contains '-' or '_', which are base64url characters`),
  },
  {
    description: `a certificate in base64url, with '_' where base64 has '/'`,
    certificate: leafCertificate.replace(/\//g, '_'),
    message: base64Problem(`it contains '-' or '_', which are base64url characters`),
  },
  {
    description: 'a certificate without the padding its length needs',
    certificate: rootCertificate.replace(/=+$/, ''),
    message: base64Problem(
      `its '=' padding is wrong: base64 is padded with at most two '=' at its end, to a multiple of 4 characters`
    ),
  },
  {
    description: 'a certificate with padding its length does not need',
    certificate: `${leafCertificate}==`,
    message: base64Problem(
      `its '=' padding is wrong: base64 is padded with at most two '=' at its end, to a multiple of 4 characters`
    ),
  },
  {
    description: `a certificate with a '=' too many`,
    certificate: `${rootCertificate}=`,
    message: base64Problem(
      `its '=' padding is wrong: base64 is padded with at most two '=' at its end, to a multiple of 4 characters`
    ),
  },
  {
    description: 'a certificate whose last character sets bits that encode no byte',
    // 'w' and 'x' differ in the last 4 bits of the character, which encode nothing before '=='
    certificate: rootCertificate.replace(/w==$/, 'x=='),
    message: base64Problem('it is not the canonical encoding of its bytes: the bits after the last byte are not zero'),
  },
  {
    description: 'a certificate with line breaks, as PEM has them',
    certificate: leafCertificate.replace(/(.{64})/g, '$1\n'),
    message: base64Problem('it contains whitespace'),
  },
  {
    description: 'a certificate followed by a line break',
    certificate: `${leafCertificate}\n`,
    message: base64Problem('it contains whitespace'),
  },
  {
    description: 'a certificate with a character outside the base64 alphabet',
    certificate: `${leafCertificate.slice(0, -4)}.AAA`,
    message: base64Problem('it contains a character outside the base64 alphabet'),
  },
  {
    description: 'an empty string',
    certificate: '',
    message: base64Problem('it is empty'),
  },
  {
    description: 'base64 of text rather than of DER',
    certificate: base64.encode(stringToBytes('certificate')),
    message: derProblem('they do not start with the SEQUENCE tag (0x30)'),
  },
  {
    description: 'a DER SET rather than a SEQUENCE',
    certificate: encodeBytes(0x31, 0x00),
    message: derProblem('they do not start with the SEQUENCE tag (0x30)'),
  },
  {
    description: 'a SEQUENCE tag without a length',
    certificate: encodeBytes(0x30),
    message: derProblem('they end after the tag, without a length'),
  },
  {
    description: 'a certificate without its last byte',
    certificate: base64.encode(leafBytes.subarray(0, leafBytes.length - 1)),
    message: derProblem('the SEQUENCE is truncated: its length is 395 byte(s), but only 394 byte(s) follow'),
  },
  {
    description: 'a SEQUENCE whose length is longer than the bytes that follow',
    certificate: encodeBytes(0x30, 0x05, 0x00),
    message: derProblem('the SEQUENCE is truncated: its length is 5 byte(s), but only 1 byte(s) follow'),
  },
  {
    description: 'a SEQUENCE whose bytes end inside its length',
    certificate: encodeBytes(0x30, 0x82, 0x01),
    message: derProblem('they end inside the length'),
  },
  {
    description: 'a SEQUENCE whose length is encoded in more than 4 bytes',
    certificate: encodeBytes(0x30, 0x85, 0x01, 0x00, 0x00, 0x00, 0x00),
    message: derProblem('the length is encoded in more than 4 bytes'),
  },
  {
    description: 'a SEQUENCE with an indefinite length (0x80)',
    certificate: encodeBytes(0x30, 0x80, 0x02, 0x01, 0x00, 0x00, 0x00),
    message: derProblem('the length is indefinite (0x80), which DER does not allow'),
  },
  {
    description: 'a SEQUENCE whose length below 128 takes the long form',
    certificate: encodeBytes(0x30, 0x81, 0x01, 0x00),
    message: derProblem('the length is not minimally encoded, as DER requires'),
  },
  {
    description: 'a SEQUENCE whose long form length starts with a zero byte',
    certificate: base64.encode(concatBytes(new Uint8Array([0x30, 0x82, 0x00, 0x80]), new Uint8Array(128))),
    message: derProblem('the length is not minimally encoded, as DER requires'),
  },
  {
    description: 'a certificate followed by a byte',
    certificate: base64.encode(concatBytes(leafBytes, new Uint8Array([0x00]))),
    message: derProblem('1 byte(s) follow the SEQUENCE'),
  },
  {
    description: 'two certificates in one entry',
    certificate: base64.encode(concatBytes(leafBytes, rootBytes)),
    message: derProblem(`${rootBytes.length} byte(s) follow the SEQUENCE`),
  },
]

const ecJwk = { kty: 'EC', crv: 'P-256', x: 'eA', y: 'eQ' }

describe.each([
  ['the JWS protected header', (x5c: unknown) => zJwsProtectedHeader.safeParse({ alg: 'ES256', x5c })],
  ['a JWK', (x5c: unknown) => zJwk.safeParse({ ...ecJwk, x5c })],
  ['the JWE header', (x5c: unknown) => zJweHeader.safeParse({ alg: 'ECDH-ES', enc: 'A128GCM', x5c })],
])('the x5c of %s', (_, parse) => {
  it('accepts a certificate chain of a leaf and its root', () => {
    expect(parse(certificateChain)).toMatchObject({ success: true, data: { x5c: certificateChain } })
  })

  it('accepts the certificate of RFC 7517 Appendix B', () => {
    expect(parse([rfc7517Certificate])).toMatchObject({ success: true, data: { x5c: [rfc7517Certificate] } })
  })

  it('accepts base64 of an empty SEQUENCE, as the certificate itself is not parsed', () => {
    expect(parse([emptySequence])).toMatchObject({ success: true, data: { x5c: [emptySequence] } })
  })

  it('rejects a chain without certificates', () => {
    expect(parse([]).error?.issues).toEqual([
      expect.objectContaining({ path: ['x5c'], message: 'Expected a certificate chain of at least one certificate' }),
    ])
  })

  it.each(rejectedCertificates)('rejects $description', ({ certificate, message }) => {
    expect(parse([certificate]).error?.issues).toEqual([expect.objectContaining({ path: ['x5c', 0], message })])
  })

  it('names the entry that is rejected', () => {
    const certificate = leafCertificate.replace(/\+/g, '-')

    expect(parse([rootCertificate, certificate]).error?.issues).toEqual([
      expect.objectContaining({ path: ['x5c', 1], message: expect.stringContaining('base64url') }),
    ])
  })

  it('names every entry that is rejected', () => {
    const issues = parse(['', leafCertificate, encodeBytes(0x31, 0x00)]).error?.issues

    expect(issues?.map(({ path }) => path)).toEqual([
      ['x5c', 0],
      ['x5c', 2],
    ])
  })
})

describe('the x5c schemas for the schemas of other packages', () => {
  it('are exported from the package entry point', () => {
    expect(entryPoint.zX5c).toBe(zX5c)
    expect(entryPoint.zX5cCertificate).toBe(zX5cCertificate)
  })

  it('accept a certificate chain on its own', () => {
    expect(zX5c.parse(certificateChain)).toEqual(certificateChain)
  })

  it('report a rejected entry of a chain by its index', () => {
    expect(zX5c.safeParse([leafCertificate, encodeBytes(0x30)]).error?.issues).toEqual([
      expect.objectContaining({ path: [1], message: derProblem('they end after the tag, without a length') }),
    ])
  })

  it('reject a single certificate that is not the canonical encoding of its bytes', () => {
    // Decodes to the same empty SEQUENCE as 'MAA=', but sets a bit after the last byte
    expect(zX5cCertificate.safeParse('MAB=').error?.issues).toEqual([
      expect.objectContaining({
        path: [],
        message: base64Problem(
          'it is not the canonical encoding of its bytes: the bits after the last byte are not zero'
        ),
      }),
    ])
  })
})

describe('an x5c that is not valid in a token', () => {
  it('fails parsing a compact JWS with a JoseValidationError naming the entry', () => {
    const jws = unsignedCompactJws({ alg: 'ES256', x5c: [leafCertificate, rootCertificate.replace(/\//g, '_')] }, {})

    expect(() => parseJws({ jws })).toThrow(
      joseError(JoseValidationError, `which are base64url characters at "x5c[1]"`)
    )
  })

  it('fails parsing a compact JWS whose x5c holds no certificate with a JoseValidationError', () => {
    expect(() => parseJws({ jws: unsignedCompactJws({ alg: 'ES256', x5c: [] }, {}) })).toThrow(
      joseError(JoseValidationError, 'Expected a certificate chain of at least one certificate at "x5c"')
    )
  })

  it('fails verifying a JWT whose x5c holds no certificate before the verification callback is called', async () => {
    let callbackCalled = false
    const jwt = unsignedCompactJws({ alg: 'ES256', x5c: [] }, {})

    await expect(
      verifyJwt({
        jwt,
        verifyJwsCallback: () => {
          callbackCalled = true
          return { verified: true, signerJwk: ecJwk }
        },
      })
    ).rejects.toThrow(joseError(JoseValidationError, 'Expected a certificate chain of at least one certificate'))
    expect(callbackCalled).toBe(false)
  })

  it('fails parsing a JWS whose jwk header parameter carries an x5c that is not DER, naming the entry', () => {
    const jws = unsignedCompactJws({ alg: 'ES256', jwk: { ...ecJwk, x5c: [base64.encode(stringToBytes('cert'))] } }, {})

    expect(() => parseJws({ jws })).toThrow(
      joseError(JoseValidationError, 'they do not start with the SEQUENCE tag (0x30) at "jwk.x5c[0]"')
    )
  })

  it('fails decoding the header of a compact JWE whose x5c holds no certificate', () => {
    const header = base64url.encode(stringToBytes(JSON.stringify({ alg: 'ECDH-ES', enc: 'A128GCM', x5c: [] })))
    const jwe = `${header}..aXY.Y3Q.dGFn`

    expect(() => decodeJwtHeader({ jwt: jwe })).toThrow(
      joseError(JoseValidationError, 'Expected a certificate chain of at least one certificate at "x5c"')
    )
  })

  it('fails parsing a JWK Set with a key whose x5c is base64url, naming the key and the entry', () => {
    const result = zJwkSet.safeParse({ keys: [ecJwk, { ...ecJwk, x5c: [leafCertificate.replace(/\+/g, '-')] }] })

    expect(result.error?.issues).toEqual([
      expect.objectContaining({ path: ['keys', 1, 'x5c', 0], message: expect.stringContaining('base64url') }),
    ])
  })

  it('refuses to sign a JWT for an x5c signer whose certificate is base64url, before the signing callback is called', async () => {
    const { publicJwk } = await createEs256Context()
    let callbackCalled = false
    const x5c = [leafCertificate.replace(/\//g, '_')]

    await expect(
      signJwt({
        header: { x5c },
        payload: {},
        signer: { method: 'x5c', alg: 'ES256', x5c },
        signJwsCallback: () => {
          callbackCalled = true
          return { signature: 'c2lnbmF0dXJl', signerJwk: publicJwk }
        },
      })
    ).rejects.toThrow(joseError(JoseValidationError, `which are base64url characters at "x5c[0]"`))
    expect(callbackCalled).toBe(false)
  })
})
