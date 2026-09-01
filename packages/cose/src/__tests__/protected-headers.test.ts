import { hex } from '@owf/identity-common'
import { Tag } from 'cbor-x'
import { describe, expect, test } from 'vitest'
import z from 'zod'
import {
  type CoseHeadersFor,
  Cwt,
  CwtPayload,
  cborEncode,
  extendCoseHeaderClaims,
  Mac0,
  MacAlgorithm,
  ProtectedHeaders,
  protectedHeadersSchema,
  RegisteredCwtHeaderClaimKey,
  Sign1,
  SignatureAlgorithm,
} from '../../src'
import { mac0Context, macKey, sign1Context, signKey } from './context'

// NOTE: compared as hex, because the CBOR decoder attaches a cached `dataView` to a buffer it reads
// from, which a structural comparison of two `Uint8Array`s then trips over.
const toHex = (bytes: Uint8Array) => hex.encode(bytes)

// `{1: -7}` with the algorithm written as `38 06` rather than the shortest form `26`, and `{1: 5}`
// as `18 05` rather than `05`. Valid CBOR that we would never encode this way, which is the point:
// what the issuer signed is these bytes.
const nonCanonicalSignHeaders = hex.decode('a1013806')
const canonicalSignHeaders = hex.decode('a10126')
const nonCanonicalMacHeaders = hex.decode('a1011805')

const payload = new Uint8Array([1, 2, 3])

const token = (tag: number, protectedHeaders: Uint8Array, signatureOrTag: Uint8Array) =>
  cborEncode(new Tag([protectedHeaders, new Map(), payload, signatureOrTag], tag))

describe('ProtectedHeaders byte preservation', () => {
  test('a decoded Sign1 verifies against the bytes the issuer signed, not our re-encoding', async () => {
    const signature = await sign1Context.sign({
      toBeSigned: cborEncode(['Signature1', nonCanonicalSignHeaders, new Uint8Array(), payload]),
      key: signKey,
      algorithm: SignatureAlgorithm.ES256,
    })
    const sign1 = Sign1.decode(token(Sign1.tag, nonCanonicalSignHeaders, signature))

    expect(toHex(sign1.protectedHeaders.encodedStructure)).toBe(toHex(nonCanonicalSignHeaders))
    expect(sign1.protectedHeaders.headers.get(RegisteredCwtHeaderClaimKey.Algorithm)).toBe(SignatureAlgorithm.ES256)
    await expect(sign1.verifySignature({ key: signKey }, sign1Context)).resolves.toBe(true)

    // The same headers built from the decoded map encode to the canonical form, which is what the
    // signature would have been checked against without the retained bytes.
    const rebuilt = ProtectedHeaders.create({
      protectedHeaders: sign1.protectedHeaders.headers.toMap() as Map<number, unknown>,
    })
    expect(toHex(rebuilt.encodedStructure)).toBe(toHex(canonicalSignHeaders))
  })

  test('a decoded Mac0 authenticates against those bytes too', async () => {
    const authenticationTag = await mac0Context.authenticate({
      toBeAuthenticated: cborEncode(['MAC0', nonCanonicalMacHeaders, payload]),
      key: macKey,
    })
    const mac0 = Mac0.decode(token(Mac0.tag, nonCanonicalMacHeaders, authenticationTag))

    expect(toHex(mac0.protectedHeaders.encodedStructure)).toBe(toHex(nonCanonicalMacHeaders))
    expect(mac0.algorithm).toBe(MacAlgorithm.HS256)
    await expect(mac0.verifyAuthenticationCode({ key: macKey }, mac0Context)).resolves.toBe(true)
  })

  test('changing a header drops the retained bytes', async () => {
    const signature = await sign1Context.sign({
      toBeSigned: cborEncode(['Signature1', nonCanonicalSignHeaders, new Uint8Array(), payload]),
      key: signKey,
      algorithm: SignatureAlgorithm.ES256,
    })
    const sign1 = Sign1.decode(token(Sign1.tag, nonCanonicalSignHeaders, signature))

    sign1.protectedHeaders.headers.set(RegisteredCwtHeaderClaimKey.Algorithm, SignatureAlgorithm.ES256)

    // The headers now encode from the map, so the signature over the original bytes no longer
    // verifies — which is correct: these are no longer the headers the issuer signed.
    expect(toHex(sign1.protectedHeaders.encodedStructure)).toBe(toHex(canonicalSignHeaders))
    await expect(sign1.verifySignature({ key: signKey }, sign1Context)).resolves.toBe(false)
  })

  test('deleting a header drops them as well', () => {
    const headers = ProtectedHeaders.fromEncodedStructure(nonCanonicalSignHeaders)

    expect(toHex(headers.encodedStructure)).toBe(toHex(nonCanonicalSignHeaders))
    headers.headers.delete(RegisteredCwtHeaderClaimKey.Algorithm)
    expect(toHex(headers.encodedStructure)).toBe('a0')
  })

  test('markModified drops them for a change the map cannot see', () => {
    const headers = ProtectedHeaders.fromEncodedStructure(nonCanonicalSignHeaders)

    // Standing in for an in-place change of a header value, e.g. `headers.get(x5chain)[0] = ...`,
    // which does not go through the map and so does not drop the bytes on its own.
    expect(toHex(headers.encodedStructure)).toBe(toHex(nonCanonicalSignHeaders))
    headers.markModified()
    expect(toHex(headers.encodedStructure)).toBe(toHex(canonicalSignHeaders))
  })

  test('headers that were built rather than decoded encode from the map', () => {
    const headers = ProtectedHeaders.create({
      protectedHeaders: new Map<number, unknown>([[RegisteredCwtHeaderClaimKey.Algorithm, SignatureAlgorithm.ES256]]),
    })

    expect(toHex(headers.encodedStructure)).toBe(toHex(canonicalSignHeaders))
    headers.headers.set(RegisteredCwtHeaderClaimKey.KeyId, new Uint8Array([1]))
    expect(toHex(headers.encodedStructure)).toBe('a201260441 01'.replace(/ /g, ''))
  })
})

describe('Cwt protected header byte preservation', () => {
  const exampleTyp = 'application/example+cwt'
  const exampleHeaderClaims = extendCoseHeaderClaims([
    [RegisteredCwtHeaderClaimKey.Typ, z.literal(exampleTyp)],
  ] as const)

  class ExampleProtectedHeaders extends ProtectedHeaders<CoseHeadersFor<typeof exampleHeaderClaims>> {
    public static override get encodingSchema() {
      return protectedHeadersSchema(exampleHeaderClaims)
    }
  }

  // `{1: -7, 16: 'application/example+cwt'}`, again with a non-shortest-form algorithm.
  const headers = hex.decode(`a20138061077${Buffer.from(exampleTyp).toString('hex')}`)

  test('survives the re-decode through the CWT type header class', async () => {
    const claims = CwtPayload.create({ subject: 'https://subject.example' })
    const signature = await sign1Context.sign({
      toBeSigned: cborEncode(['Signature1', headers, new Uint8Array(), claims.encode()]),
      key: signKey,
      algorithm: SignatureAlgorithm.ES256,
    })
    const encoded = cborEncode(new Tag([headers, new Map(), claims.encode(), signature], Sign1.tag))

    const cwt = Cwt.fromToken(encoded, { payload: CwtPayload, protectedHeaders: ExampleProtectedHeaders })

    expect(cwt.protectedHeaders).toBeInstanceOf(ExampleProtectedHeaders)
    expect(cwt.typ).toBe(exampleTyp)
    expect(toHex(cwt.protectedHeaders.encodedStructure)).toBe(toHex(headers))
    await expect(
      cwt.verify({ key: signKey, expectedSubject: 'https://subject.example' }, { sign1: sign1Context })
    ).resolves.toBeUndefined()
  })
})
