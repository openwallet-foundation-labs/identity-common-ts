import { base64url, stringToBytes } from '@owf/identity-common'
import { describe, expect, it } from 'vitest'
import type { SignJwsCallback, VerifyJwsCallback } from '../callbacks'
import { JoseAlgorithmNotAllowedError, JoseParseError, JoseSignatureVerificationError } from '../error'
import type { Jwk } from '../jwk/z-jwk'
import { parseJws } from '../jws/parse-jws'
import { signCompactJws } from '../jws/sign-jws'
import { verifyJwsSignature } from '../jws/verify-jws'
import { decodeJwt } from '../jwt/decode-jwt'
import { verifyJwt } from '../jwt/verify-jwt'
import { claimIssue, validationIssue } from './context'

/**
 * The examples of the JOSE RFCs, verified with WebCrypto against the keys the RFCs give.
 *
 * Verifying a signature someone else computed is what shows that the signing input is taken from
 * the token byte for byte: the RFC 7515 examples have line breaks in their JSON, which re-encoding
 * the parsed header or payload would lose.
 */

/** Matches a thrown error by its class and a part of its message. */
const joseError = (type: { name: string }, message: string) =>
  expect.objectContaining({ name: type.name, message: expect.stringContaining(message) })

const webCryptoParameters: Record<
  string,
  {
    importParams: Algorithm | EcKeyImportParams | HmacImportParams | RsaHashedImportParams
    signParams: Algorithm | EcdsaParams
  }
> = {
  HS256: { importParams: { name: 'HMAC', hash: 'SHA-256' }, signParams: { name: 'HMAC' } },
  RS256: { importParams: { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, signParams: { name: 'RSASSA-PKCS1-v1_5' } },
  ES256: { importParams: { name: 'ECDSA', namedCurve: 'P-256' }, signParams: { name: 'ECDSA', hash: 'SHA-256' } },
  ES512: { importParams: { name: 'ECDSA', namedCurve: 'P-521' }, signParams: { name: 'ECDSA', hash: 'SHA-512' } },
  EdDSA: { importParams: { name: 'Ed25519' }, signParams: { name: 'Ed25519' } },
}

/** A verification callback that verifies with `jwk`, for the algorithm the signer says the JWS uses. */
const verifyWith =
  (jwk: Jwk): VerifyJwsCallback =>
  async (signer, { signingInputBytes, signature }) => {
    const { importParams, signParams } = webCryptoParameters[signer.alg]
    const key = await globalThis.crypto.subtle.importKey('jwk', jwk as JsonWebKey, importParams, false, ['verify'])
    const verified = await globalThis.crypto.subtle.verify(
      signParams,
      key,
      base64url.decode(signature) as Uint8Array<ArrayBuffer>,
      signingInputBytes as Uint8Array<ArrayBuffer>
    )

    return verified ? { verified: true, signerJwk: jwk } : { verified: false }
  }

/** A signing callback that signs with the private `jwk`, reporting `publicJwk` as the key it signed with. */
const signWith =
  (privateJwk: Jwk, publicJwk: Jwk): SignJwsCallback =>
  async (signer, { signingInputBytes }) => {
    const { importParams, signParams } = webCryptoParameters[signer.alg]
    const key = await globalThis.crypto.subtle.importKey('jwk', privateJwk as JsonWebKey, importParams, false, ['sign'])
    const signature = await globalThis.crypto.subtle.sign(signParams, key, signingInputBytes as Uint8Array<ArrayBuffer>)

    return { signature: base64url.encode(new Uint8Array(signature)), signerJwk: publicJwk }
  }

// The JWS Payload shared by the examples of RFC 7515 Appendix A.1, A.2, A.3, A.6 and A.7
const examplePayload = 'eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ'
const examplePayloadJson = '{"iss":"joe",\r\n "exp":1300819380,\r\n "http://example.com/is_root":true}'

// RFC 7515 Appendix A.1, which is also the example JWT of RFC 7519 section 3.1
const hmacExampleHeader = 'eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9'
const hmacExample = `${hmacExampleHeader}.${examplePayload}.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk`
const hmacJwk = {
  kty: 'oct',
  k: 'AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow',
}

// RFC 7515 Appendix A.2
const rsaSignature =
  'cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqvhJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrBp0igcN_IoypGlUPQGe77Rw'
const rsaExample = `eyJhbGciOiJSUzI1NiJ9.${examplePayload}.${rsaSignature}`
const rsaPublicJwk = {
  kty: 'RSA',
  n: 'ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddxHmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMsD1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSHSXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdVMTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ',
  e: 'AQAB',
}

// RFC 7515 Appendix A.3
const p256Signature = 'DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q'
const p256Example = `eyJhbGciOiJFUzI1NiJ9.${examplePayload}.${p256Signature}`
const p256PublicJwk = {
  kty: 'EC',
  crv: 'P-256',
  x: 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU',
  y: 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0',
}

// RFC 7515 Appendix A.4
const p521Example =
  'eyJhbGciOiJFUzUxMiJ9.UGF5bG9hZA.AdwMgeerwtHoh-l192l60hp9wAHZFVJbLfD_UxMi70cwnZOYaRI1bKPWROc-mZZqwqT2SI-KGDKB34XO0aw_7XdtAG8GaSwFKdCAPZgoXD2YBJZCPEX3xKpRwcdOO8KpEHwJjyqOgzDO7iKvU8vcnwNrmxYbSW9ERBXukOXolLzeO_Jn'
const p521PublicJwk = {
  kty: 'EC',
  crv: 'P-521',
  x: 'AekpBQ8ST8a8VcfVOTNl353vSrDCLLJXmPk06wTjxrrjcBpXp5EOnYG_NjFZ6OvLFV1jSfS9tsz4qUxcWceqwQGk',
  y: 'ADSmRA43Z1DSNx_RvcLI87cdL07l6jQyyBXMoxVg_l2Th-x3S1WDhjDly79ajL4Kkd0AZMaZmh9ubmf63e3kyMj2',
}

// RFC 7515 Appendix A.5, which is also the unsecured JWT of RFC 7519 section 6.1
const unsecuredExample = `eyJhbGciOiJub25lIn0.${examplePayload}.`

// RFC 8037 Appendix A.1, A.2 and A.4
const ed25519PublicJwk = { kty: 'OKP', crv: 'Ed25519', x: '11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo' }
const ed25519PrivateJwk = { ...ed25519PublicJwk, d: 'nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A' }
const ed25519Example =
  'eyJhbGciOiJFZERTQSJ9.RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc.hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt9g7sVvpAr_MuM0KAg'

// RFC 7797 section 4, which uses the HMAC key of RFC 7515 Appendix A.1
const encodedPayloadExample = 'eyJhbGciOiJIUzI1NiJ9.JC4wMg.5mvfOroL-g7HyqJoozehmsaqmvTYGEq5jTI1gVvoEoQ'
const unencodedPayloadHeader = 'eyJhbGciOiJIUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19'
const unencodedPayloadSignature = 'A5dxf2s96_n5FLueVuW1Z_vh161FwXZC4YLPff6dmDY'

// 2011-03-22T18:43:00Z is the `exp` of the example claims set
const beforeExampleExpiry = new Date('2011-03-22T18:00:00Z')

describe('RFC 7515 Appendix A.1: HMAC SHA-256', () => {
  it('rejects the HS256 example before the callback is called while symmetric algorithms are not allowed', async () => {
    let callbackCalled = false
    const verifyJwsCallback: VerifyJwsCallback = (...args) => {
      callbackCalled = true
      return verifyWith(hmacJwk)(...args)
    }

    await expect(verifyJwsSignature({ jws: parseJws({ jws: hmacExample }), verifyJwsCallback })).rejects.toThrow(
      joseError(JoseAlgorithmNotAllowedError, `uses the symmetric algorithm 'HS256'`)
    )
    expect(callbackCalled).toBe(false)
  })

  it('verifies the HS256 example when symmetric algorithms are allowed', async () => {
    const { signer } = await verifyJwsSignature({
      jws: parseJws({ jws: hmacExample }),
      verifyJwsCallback: verifyWith(hmacJwk),
      allowedAlgorithms: ['HS256'],
      allowSymmetricAlgorithms: true,
    })

    expect(signer).toEqual({ method: 'custom', alg: 'HS256', kid: undefined, publicJwk: hmacJwk })
  })

  it('takes the signing input from the token as it was received rather than re-encoding the parsed header', () => {
    // The header JSON contains a CRLF and a space, which encoding the parsed header would drop
    expect(parseJws({ jws: hmacExample }).signingInput).toBe(`${hmacExampleHeader}.${examplePayload}`)
  })
})

describe('RFC 7519 section 3.1: example JWT', () => {
  it('decodes the header and the claims set of the example JWT', () => {
    const { header, payload } = decodeJwt({ jwt: hmacExample })

    expect(header).toEqual({ typ: 'JWT', alg: 'HS256' })
    expect(payload).toEqual({ iss: 'joe', exp: 1300819380, 'http://example.com/is_root': true })
  })

  it('returns the claims set bytes exactly as they were carried, line breaks included', () => {
    expect(decodeJwt({ jwt: hmacExample }).payloadBytes).toEqual(stringToBytes(examplePayloadJson))
  })

  it('verifies the example JWT at a time before its exp', async () => {
    const { payload } = await verifyJwt({
      jwt: hmacExample,
      verifyJwsCallback: verifyWith(hmacJwk),
      allowSymmetricAlgorithms: true,
      now: beforeExampleExpiry,
    })

    expect(payload).toEqual({ iss: 'joe', exp: 1300819380, 'http://example.com/is_root': true })
  })

  it('rejects the example JWT as expired once its exp and the clock skew have passed', async () => {
    await expect(
      verifyJwt({
        jwt: hmacExample,
        verifyJwsCallback: verifyWith(hmacJwk),
        allowSymmetricAlgorithms: true,
        now: new Date('2011-03-22T18:43:31Z'),
      })
    ).rejects.toThrow(claimIssue('exp', 'expired'))
  })
})

describe('RFC 7515 Appendix A.2: RSASSA-PKCS1-v1_5 SHA-256', () => {
  it('verifies the RS256 example with the public key of the RFC', async () => {
    const { signer } = await verifyJwsSignature({
      jws: parseJws({ jws: rsaExample }),
      verifyJwsCallback: verifyWith(rsaPublicJwk),
      allowedAlgorithms: ['RS256'],
    })

    expect(signer).toEqual({ method: 'custom', alg: 'RS256', kid: undefined, publicJwk: rsaPublicJwk })
  })

  it('rejects the RS256 signature of the example over a different payload', async () => {
    // The header and signature of A.2, with the payload of A.4
    const jws = parseJws({ jws: `eyJhbGciOiJSUzI1NiJ9.UGF5bG9hZA.${rsaSignature}` })

    await expect(verifyJwsSignature({ jws, verifyJwsCallback: verifyWith(rsaPublicJwk) })).rejects.toThrow(
      joseError(JoseSignatureVerificationError, 'Error during verification of the JWS.')
    )
  })
})

describe('RFC 7515 Appendix A.3: ECDSA P-256 SHA-256', () => {
  it('verifies the ES256 example with the public key of the RFC', async () => {
    const { signer } = await verifyJwsSignature({
      jws: parseJws({ jws: p256Example }),
      verifyJwsCallback: verifyWith(p256PublicJwk),
      allowedAlgorithms: ['ES256'],
    })

    expect(signer).toEqual({ method: 'custom', alg: 'ES256', kid: undefined, publicJwk: p256PublicJwk })
  })

  it('verifies the ES256 example as a JWT at a time before its exp', async () => {
    const { header, payload } = await verifyJwt({
      jwt: p256Example,
      verifyJwsCallback: verifyWith(p256PublicJwk),
      allowedAlgorithms: ['ES256'],
      now: beforeExampleExpiry,
    })

    expect(header).toEqual({ alg: 'ES256' })
    expect(payload).toEqual({ iss: 'joe', exp: 1300819380, 'http://example.com/is_root': true })
  })
})

describe('RFC 7515 Appendix A.4: ECDSA P-521 SHA-512', () => {
  it('verifies the ES512 example with the public key of the RFC', async () => {
    const jws = parseJws({ jws: p521Example })
    const { signer } = await verifyJwsSignature({ jws, verifyJwsCallback: verifyWith(p521PublicJwk) })

    expect(signer).toEqual({ method: 'custom', alg: 'ES512', kid: undefined, publicJwk: p521PublicJwk })
  })

  it('returns the payload of the ES512 example, which is not JSON', () => {
    expect(parseJws({ jws: p521Example }).payload).toEqual(stringToBytes('Payload'))
  })

  it('rejects the ES512 example as a JWT, as its payload is not a JSON claims set', () => {
    expect(() => decodeJwt({ jwt: p521Example })).toThrow(
      joseError(JoseParseError, 'Unable to decode the JWT payload, it is not valid base64url encoded JSON')
    )
  })
})

describe('RFC 7515 Appendix A.5: unsecured JWS', () => {
  // Rejected for its empty signature, a parse error, before its `alg` of `none` is looked at
  it('rejects the unsecured example as a JWS', () => {
    expect(() => parseJws({ jws: unsecuredExample })).toThrow(JoseParseError)
  })

  it('rejects the unsecured example as a JWT', () => {
    expect(() => decodeJwt({ jwt: unsecuredExample })).toThrow(JoseParseError)
  })
})

describe('RFC 7515 Appendix A.6: general JWS JSON serialization', () => {
  const generalExample = {
    payload: examplePayload,
    signatures: [
      { protected: 'eyJhbGciOiJSUzI1NiJ9', header: { kid: '2010-12-29' }, signature: rsaSignature },
      {
        protected: 'eyJhbGciOiJFUzI1NiJ9',
        header: { kid: 'e9bc097a-ce51-4036-9562-d2ade882db0d' },
        signature: p256Signature,
      },
    ],
  }

  it('verifies the first signature, the RS256 one, by default', async () => {
    const jws = parseJws({ jws: generalExample })
    const { signer } = await verifyJwsSignature({ jws, verifyJwsCallback: verifyWith(rsaPublicJwk) })

    expect(signer.alg).toBe('RS256')
  })

  it('verifies the second signature, the ES256 one, when it is selected', async () => {
    const jws = parseJws({ jws: generalExample, signatureIndex: 1 })
    const { signer } = await verifyJwsSignature({ jws, verifyJwsCallback: verifyWith(p256PublicJwk) })

    expect(signer.alg).toBe('ES256')
  })

  it('computes the signing input of each signature from its own protected header', () => {
    expect(parseJws({ jws: generalExample, signatureIndex: 0 }).signingInput).toBe(
      `eyJhbGciOiJSUzI1NiJ9.${examplePayload}`
    )
    expect(parseJws({ jws: generalExample, signatureIndex: 1 }).signingInput).toBe(
      `eyJhbGciOiJFUzI1NiJ9.${examplePayload}`
    )
  })

  it('returns the unprotected header of the selected signature', () => {
    const jws = parseJws({ jws: generalExample, signatureIndex: 1 })

    expect(jws.unprotectedHeader).toEqual({ kid: 'e9bc097a-ce51-4036-9562-d2ade882db0d' })
  })
})

describe('RFC 7515 Appendix A.7: flattened JWS JSON serialization', () => {
  const flattenedExample = {
    payload: examplePayload,
    protected: 'eyJhbGciOiJFUzI1NiJ9',
    header: { kid: 'e9bc097a-ce51-4036-9562-d2ade882db0d' },
    signature: p256Signature,
  }

  it('verifies the flattened example', async () => {
    const jws = parseJws({ jws: flattenedExample })
    const { signer } = await verifyJwsSignature({ jws, verifyJwsCallback: verifyWith(p256PublicJwk) })

    expect(signer).toEqual({ method: 'custom', alg: 'ES256', kid: undefined, publicJwk: p256PublicJwk })
  })

  it('reads the flattened example as the same signing input as the compact A.3 example', () => {
    expect(parseJws({ jws: flattenedExample }).signingInput).toBe(parseJws({ jws: p256Example }).signingInput)
  })
})

describe('RFC 7797 section 4: the b64 header parameter', () => {
  it('verifies the example with an encoded payload', async () => {
    const jws = parseJws({ jws: encodedPayloadExample })
    await verifyJwsSignature({ jws, verifyJwsCallback: verifyWith(hmacJwk), allowSymmetricAlgorithms: true })

    expect(jws.payload).toEqual(stringToBytes('$.02'))
  })

  it('reproduces the example with an encoded payload byte for byte when signing it', async () => {
    const { compact } = await signCompactJws({
      protectedHeader: { alg: 'HS256' },
      payload: '$.02',
      signer: { method: 'custom', alg: 'HS256' },
      signJwsCallback: signWith(hmacJwk, hmacJwk),
    })

    expect(compact).toBe(encodedPayloadExample)
  })

  it('verifies the example with an unencoded payload that is detached from the compact serialization', async () => {
    const jws = parseJws({
      jws: `${unencodedPayloadHeader}..${unencodedPayloadSignature}`,
      detachedPayload: '$.02',
      understoodCriticalParameters: ['b64'],
    })
    await verifyJwsSignature({ jws, verifyJwsCallback: verifyWith(hmacJwk), allowSymmetricAlgorithms: true })

    expect(jws.signingInput).toBe(`${unencodedPayloadHeader}.$.02`)
  })

  it('verifies the example with an unencoded payload carried in the flattened JSON serialization', async () => {
    const jws = parseJws({
      jws: { protected: unencodedPayloadHeader, payload: '$.02', signature: unencodedPayloadSignature },
      understoodCriticalParameters: ['b64'],
    })
    await verifyJwsSignature({ jws, verifyJwsCallback: verifyWith(hmacJwk), allowSymmetricAlgorithms: true })

    expect(jws.payload).toEqual(stringToBytes('$.02'))
  })

  it('rejects the example with an unencoded payload when the caller does not understand b64', () => {
    expect(() =>
      parseJws({ jws: `${unencodedPayloadHeader}..${unencodedPayloadSignature}`, detachedPayload: '$.02' })
    ).toThrow(validationIssue(['crit', 0], 'unsupported_crit'))
  })
})

describe('RFC 8037 Appendix A.4 and A.5: Ed25519', () => {
  it('verifies the Ed25519 example with the public key of the RFC', async () => {
    const jws = parseJws({ jws: ed25519Example })
    const { signer } = await verifyJwsSignature({ jws, verifyJwsCallback: verifyWith(ed25519PublicJwk) })

    expect(signer).toEqual({ method: 'custom', alg: 'EdDSA', kid: undefined, publicJwk: ed25519PublicJwk })
  })

  it('returns the payload of the Ed25519 example', () => {
    expect(parseJws({ jws: ed25519Example }).payload).toEqual(stringToBytes('Example of Ed25519 signing'))
  })

  it('reproduces the Ed25519 example byte for byte when signing it', async () => {
    // Ed25519 signatures are deterministic, so signing the same input with the same key gives the
    // signature of the RFC
    const { compact } = await signCompactJws({
      protectedHeader: { alg: 'EdDSA' },
      payload: 'Example of Ed25519 signing',
      signer: { method: 'custom', alg: 'EdDSA' },
      signJwsCallback: signWith(ed25519PrivateJwk, ed25519PublicJwk),
    })

    expect(compact).toBe(ed25519Example)
  })
})
