import { hex } from '@owf/identity-common'
import { Tag } from 'cbor-x'
import { describe, expect, test } from 'vitest'
import z from 'zod'
import { CborDecodeError, cborEncode } from '../cbor'
import {
  type AnyCwt,
  type CoseHeadersFor,
  CosePayloadInvalidStructureError,
  Cwt,
  CwtDetachedPayloadError,
  CwtPayload,
  CwtPayloadDecodeError,
  type CwtStaticThis,
  type CwtStructures,
  extendCoseHeaderClaims,
  extendCwtPayloadClaims,
  Mac0,
  MacAlgorithm,
  ProtectedHeaders,
  protectedHeadersSchema,
  RegisteredCwtClaimKey,
  RegisteredCwtHeaderClaimKey,
  Sign1,
  SignatureAlgorithm,
} from '../cose'
import { TypedMap } from '../utils/typed-map'
import { mac0Context, macKey, sign1Context, signKey } from './context'

describe('Cwt', () => {
  describe('Sign1 based CWT', () => {
    test('create and encode', async () => {
      const cwt = Cwt.create({
        protectedHeaders: ProtectedHeaders.create({
          protectedHeaders: new Map([[RegisteredCwtHeaderClaimKey.Algorithm, SignatureAlgorithm.ES256]]),
        }),
        unprotectedHeaders: new Map(),
        payload: CwtPayload.create({ issuer: 'coap://as.example' }),
      })

      expect(cwt.payload.issuer).toBe('coap://as.example')
      expect(cwt.protectedHeaders).toBeDefined()
    })

    test('sign and verify with Sign1 context', async () => {
      const payload = hex.decode('a10171636f61703a2f2f61732e6578616d706c65') // {"1":"coap://as.example"}

      const sign1 = Sign1.create({
        protectedHeaders: ProtectedHeaders.create({
          protectedHeaders: new Map([[RegisteredCwtHeaderClaimKey.Algorithm, SignatureAlgorithm.ES256]]),
        }),
        unprotectedHeaders: new Map(),
        payload,
      })

      const signed = await sign1.sign({ signingKey: signKey, algorithm: SignatureAlgorithm.ES256 }, sign1Context)
      const token = signed.encode()

      const cwt = Cwt.fromToken(token, { payload: CwtPayload })
      expect(cwt.payloadBytes).toStrictEqual(payload)
      expect(cwt.payload.issuer).toBe('coap://as.example')

      const isValid = await cwt.verifySignature({ key: signKey }, sign1Context)
      expect(isValid).toBe(true)
    })

    test('fromToken and access properties', async () => {
      const payload = hex.decode('a10171636f61703a2f2f61732e6578616d706c65')

      const sign1 = Sign1.create({
        protectedHeaders: ProtectedHeaders.create({
          protectedHeaders: new Map([[RegisteredCwtHeaderClaimKey.Algorithm, SignatureAlgorithm.ES256]]),
        }),
        unprotectedHeaders: new Map(),
        payload,
      })

      const signed = await sign1.sign({ signingKey: signKey, algorithm: SignatureAlgorithm.ES256 }, sign1Context)
      const token = signed.encode()

      const cwt = Cwt.fromToken(token, { payload: CwtPayload })

      expect(cwt.asSign1).toBeDefined()
      expect(cwt.protectedHeaders).toBeDefined()
      expect(cwt.unprotectedHeaders).toBeDefined()
      expect(cwt.signatureOrTag).toBeDefined()
      expect(cwt.signatureOrTag).toStrictEqual(signed.signature)
    })
  })

  describe('Mac0 based CWT', () => {
    test('create and encode', async () => {
      const cwt = Cwt.create({
        protectedHeaders: ProtectedHeaders.create({
          protectedHeaders: new Map([[RegisteredCwtHeaderClaimKey.Algorithm, MacAlgorithm.HS256]]),
        }),
        unprotectedHeaders: new Map(),
        payload: CwtPayload.create({ issuer: 'coap://as.example' }),
      })

      expect(cwt.payload.issuer).toBe('coap://as.example')
      expect(cwt.protectedHeaders).toBeDefined()
    })

    test('authenticate and verify with Mac0 context', async () => {
      const payload = hex.decode('a10171636f61703a2f2f61732e6578616d706c65')

      const mac0 = Mac0.create({
        protectedHeaders: ProtectedHeaders.create({
          protectedHeaders: new Map([[RegisteredCwtHeaderClaimKey.Algorithm, MacAlgorithm.HS256]]),
        }),
        unprotectedHeaders: new Map(),
        payload,
      })

      const authenticated = await mac0.authenticate({ key: macKey, algorithm: MacAlgorithm.HS256 }, mac0Context)
      const token = authenticated.encode()

      const cwt = Cwt.fromToken(token, { payload: CwtPayload })
      expect(cwt.payloadBytes).toStrictEqual(payload)
      expect(cwt.payload.issuer).toBe('coap://as.example')

      const isValid = await cwt.verifyAuthenticationCode({ key: macKey }, mac0Context)
      expect(isValid).toBe(true)
    })

    test('fromToken and access properties', async () => {
      const payload = hex.decode('a10171636f61703a2f2f61732e6578616d706c65')

      const mac0 = Mac0.create({
        protectedHeaders: ProtectedHeaders.create({
          protectedHeaders: new Map([[RegisteredCwtHeaderClaimKey.Algorithm, MacAlgorithm.HS256]]),
        }),
        unprotectedHeaders: new Map(),
        payload,
      })

      const authenticated = await mac0.authenticate({ key: macKey, algorithm: MacAlgorithm.HS256 }, mac0Context)
      const token = authenticated.encode()

      const cwt = Cwt.fromToken(token, { payload: CwtPayload })

      expect(cwt.asMac0).toBeDefined()
      expect(cwt.protectedHeaders).toBeDefined()
      expect(cwt.unprotectedHeaders).toBeDefined()
      expect(cwt.signatureOrTag).toBeDefined()
      expect(cwt.signatureOrTag).toStrictEqual(authenticated.tag)
    })
  })

  describe('fromToken with malformed input', () => {
    test('should throw a CborDecodeError describing the input when it is not valid cbor', () => {
      // Trailing bytes after a complete cbor value
      const token = new Uint8Array([0x0f, 0x74, 0xa1])

      expect(() => Cwt.fromToken(token, { payload: CwtPayload })).toThrow(CborDecodeError)
      expect(() => Cwt.fromToken(token, { payload: CwtPayload })).toThrow(/Unable to decode 3 bytes as CBOR/)
    })

    test.each([
      ['a number', cborEncode(15), /decoded the number value '15'/],
      ['a text string', cborEncode('hello'), /decoded the text string 'hello'/],
      ['a byte string', cborEncode(new Uint8Array([1, 2, 3])), /decoded a byte string of 3 bytes/],
      ['a map', cborEncode(new Map([['a', 1]])), /decoded an untagged map with 1 entry/],
      ['null', cborEncode(null), /decoded null/],
      [
        'an untagged cose array',
        cborEncode([new Uint8Array([0xa0]), new Map(), new Uint8Array([1, 2]), new Uint8Array([3, 4])]),
        /decoded an untagged array with 4 elements/,
      ],
      ['a value with an unrelated tag', cborEncode(new Tag([1, 2], 999)), /decoded a CBOR value tagged with tag 999/],
      [
        'a cwt tagged (tag 61) value',
        cborEncode(new Tag([1, 2], 61)),
        /decoded a CBOR value tagged with tag 61 \(the CWT tag, which must be unwrapped first\)/,
      ],
    ])('should reject %s that is valid cbor but not a cose token', (_name, token, expected) => {
      expect(() => Cwt.fromToken(token, { payload: CwtPayload })).toThrow(CosePayloadInvalidStructureError)
      expect(() => Cwt.fromToken(token, { payload: CwtPayload })).toThrow(expected)
    })
  })
})

describe('Typed Cwt payload and headers', () => {
  test('should type the registered claims of the base Cwt payload', async () => {
    const cwtId = new Uint8Array([0x0b, 0x71])
    const issuedAt = new Date(1_700_000_000 * 1000)

    const payload = CwtPayload.create({
      issuer: 'coap://as.example',
      subject: 'coap://light.example',
      audience: ['coap://audience.example'],
      issuedAt,
      expirationTime: new Date(1_700_003_600 * 1000),
      notBefore: issuedAt,
      cwtId,
      additionalClaims: new Map<number, unknown>([[1000, 'custom']]),
    })

    const cwt = Cwt.create({
      protectedHeaders: new Map<number, unknown>([
        [RegisteredCwtHeaderClaimKey.Algorithm, SignatureAlgorithm.ES256],
        [RegisteredCwtHeaderClaimKey.Typ, 'application/cwt'],
      ]),
      payload,
    })

    const token = await cwt.signAndEncode({ signingKey: signKey, algorithm: SignatureAlgorithm.ES256 }, sign1Context)
    const decoded = Cwt.fromToken(token, { payload: CwtPayload })

    expect(decoded.payload.issuer).toBe('coap://as.example')
    expect(decoded.payload.subject).toBe('coap://light.example')
    expect(decoded.payload.audience).toStrictEqual(['coap://audience.example'])
    expect(decoded.payload.issuedAt).toStrictEqual(issuedAt)
    expect(decoded.payload.notBefore).toStrictEqual(issuedAt)
    expect(decoded.payload.expirationTime).toStrictEqual(new Date(1_700_003_600 * 1000))
    expect(decoded.payload.cwtId).toStrictEqual(cwtId)
    expect(decoded.payload.getClaim(1000)).toBe('custom')

    expect(decoded.typ).toBe('application/cwt')
    expect(decoded.algorithm).toBe(SignatureAlgorithm.ES256)
    expect(await decoded.verifySignature({ key: signKey }, sign1Context)).toBe(true)
  })

  test('should leave a claim that is absent undefined', () => {
    const payload = CwtPayload.create({ issuer: 'coap://as.example' })

    expect(payload.subject).toBeUndefined()
    expect(payload.expirationTime).toBeUndefined()
    expect(payload.notBefore).toBeUndefined()
    expect(payload.issuedAt).toBeUndefined()
    expect(payload.getClaim(1000)).toBeUndefined()

    // An absent claim must not be encoded as an explicit `undefined` entry
    expect(payload.claims.size).toBe(1)
  })

  test('should not read typ or alg from the unprotected headers, but should read kid', async () => {
    const keyId = new Uint8Array([0x6b, 0x69, 0x64])

    // RFC 9596 forbids `typ` in the unprotected headers, and RFC 9052 requires `alg` to be
    // authenticated, so neither is authoritative here. `kid` is explicitly allowed to live here.
    const cwt = Cwt.create({
      protectedHeaders: new Map<number, unknown>([[RegisteredCwtHeaderClaimKey.Algorithm, SignatureAlgorithm.ES256]]),
      unprotectedHeaders: new Map<number, unknown>([
        [RegisteredCwtHeaderClaimKey.Typ, 'application/attacker+cwt'],
        [RegisteredCwtHeaderClaimKey.Algorithm, SignatureAlgorithm.EdDSA],
        [RegisteredCwtHeaderClaimKey.KeyId, keyId],
      ]),
      payload: CwtPayload.create({ issuer: 'coap://as.example' }),
    })

    const decoded = Cwt.fromToken(
      await cwt.signAndEncode({ signingKey: signKey, algorithm: SignatureAlgorithm.ES256 }, sign1Context),
      { payload: CwtPayload }
    )

    expect(decoded.typ).toBeUndefined()
    // The protected alg, not the unprotected EdDSA, and the same one verification uses
    expect(decoded.algorithm).toBe(SignatureAlgorithm.ES256)
    expect(decoded.algorithm).toBe(decoded.asSign1.algorithm)
    expect(decoded.keyId).toStrictEqual(keyId)
  })

  test('should prefer the protected kid over the unprotected one', () => {
    const cwt = Cwt.create({
      protectedHeaders: new Map<number, unknown>([[RegisteredCwtHeaderClaimKey.KeyId, new Uint8Array([1])]]),
      unprotectedHeaders: new Map<number, unknown>([[RegisteredCwtHeaderClaimKey.KeyId, new Uint8Array([2])]]),
      payload: CwtPayload.create(),
    })

    expect(cwt.keyId).toStrictEqual(new Uint8Array([1]))
  })

  test('should reject a payload whose registered claim has the wrong cbor type', async () => {
    // `iss` (1) must be a text string, this token carries a number
    const sign1 = Sign1.create({
      protectedHeaders: new Map<number, unknown>([[RegisteredCwtHeaderClaimKey.Algorithm, SignatureAlgorithm.ES256]]),
      payload: cborEncode(new Map<number, unknown>([[RegisteredCwtClaimKey.Issuer, 15]])),
    })
    const token = (
      await sign1.sign({ signingKey: signKey, algorithm: SignatureAlgorithm.ES256 }, sign1Context)
    ).encode()

    expect(() => Cwt.fromToken(token, { payload: CwtPayload })).toThrow(CwtPayloadDecodeError)
    expect(() => Cwt.fromToken(token, { payload: CwtPayload })).toThrow(/Unable to decode CWT payload/)
  })

  test('should throw a CwtDetachedPayloadError for a detached payload', async () => {
    const sign1 = Sign1.create({
      protectedHeaders: new Map<number, unknown>([[RegisteredCwtHeaderClaimKey.Algorithm, SignatureAlgorithm.ES256]]),
      payload: null,
    })
    const token = (
      await sign1.sign(
        {
          signingKey: signKey,
          algorithm: SignatureAlgorithm.ES256,
          detachedPayload: cborEncode(new Map<number, unknown>([[RegisteredCwtClaimKey.Issuer, 'coap://as.example']])),
        },
        sign1Context
      )
    ).encode()

    expect(() => Cwt.fromToken(token, { payload: CwtPayload })).toThrow(CwtDetachedPayloadError)
  })
})

describe('Extending Cwt for a specific cwt type', () => {
  enum ExampleClaimKey {
    Nickname = 65000,
  }

  enum ExampleHeaderKey {
    Profile = 65001,
  }

  const exampleCwtPayloadSchema = extendCwtPayloadClaims(
    [
      // `sub` is optional in the registered claims, but required for this cwt type
      [RegisteredCwtClaimKey.Subject, z.string()],
      [ExampleClaimKey.Nickname, z.string().exactOptional()],
    ] as const,
    { keyLabels: ExampleClaimKey }
  )

  const exampleProtectedHeaderClaims = extendCoseHeaderClaims([[ExampleHeaderKey.Profile, z.string()]] as const, {
    keyLabels: ExampleHeaderKey,
  })

  class ExampleProtectedHeaders extends ProtectedHeaders<CoseHeadersFor<typeof exampleProtectedHeaderClaims>> {
    public static override get encodingSchema() {
      return protectedHeadersSchema(exampleProtectedHeaderClaims)
    }
  }

  class ExampleCwtPayload extends CwtPayload<z.infer<typeof exampleCwtPayloadSchema>> {
    public static override get encodingSchema() {
      return exampleCwtPayloadSchema
    }

    public get nickname() {
      return this.getClaim(ExampleClaimKey.Nickname)
    }
  }

  class ExampleCwt extends Cwt<ExampleCwtPayload, ExampleProtectedHeaders> {
    public static override fromToken<T extends AnyCwt>(this: CwtStaticThis<T>, token: Uint8Array): T {
      // biome-ignore lint/complexity/noThisInStatic: dispatching to the subclass is intentional
      return super.fromToken(token, {
        payload: ExampleCwtPayload,
        protectedHeaders: ExampleProtectedHeaders,
      } as unknown as CwtStructures<T>) as T
    }
  }

  const protectedHeaderMap = new Map<number, unknown>([
    [RegisteredCwtHeaderClaimKey.Algorithm, SignatureAlgorithm.ES256],
    [RegisteredCwtHeaderClaimKey.Typ, 'application/example+cwt'],
    [ExampleHeaderKey.Profile, 'example'],
  ])

  const protectedHeaders = () => ExampleProtectedHeaders.fromDecodedStructure(TypedMap.fromMap(protectedHeaderMap))

  const signAndEncode = (cwt: ExampleCwt) =>
    cwt.signAndEncode({ signingKey: signKey, algorithm: SignatureAlgorithm.ES256 }, sign1Context)

  test('should decode into the subclass with the extended payload and headers', async () => {
    const cwt = new ExampleCwt({
      protectedHeaders: protectedHeaders(),
      payload: ExampleCwtPayload.fromDecodedStructure(
        exampleCwtPayloadSchema.parse(
          new Map<number, unknown>([
            [RegisteredCwtClaimKey.Subject, 'coap://light.example'],
            [ExampleClaimKey.Nickname, 'lamp'],
          ])
        )
      ),
    })

    const decoded = ExampleCwt.fromToken(await signAndEncode(cwt))

    expect(decoded).toBeInstanceOf(ExampleCwt)
    expect(decoded.payload).toBeInstanceOf(ExampleCwtPayload)
    // Inherited registered claims stay available on the extended payload
    expect(decoded.payload.subject).toBe('coap://light.example')
    expect(decoded.payload.nickname).toBe('lamp')
    // Both the registered and the profile specific header labels are readable
    expect(decoded.typ).toBe('application/example+cwt')
    expect(decoded.protectedHeaders.headers.get(ExampleHeaderKey.Profile)).toBe('example')
    expect(await decoded.verifySignature({ key: signKey }, sign1Context)).toBe(true)
  })

  test('should build the subclass, validated by its own schema, from create', () => {
    // `create` is inherited, so it has to construct the class it was called on rather than the base
    // one — otherwise a profile's extra requirements are silently skipped.
    const payload = ExampleCwtPayload.create({ subject: 'coap://light.example' })
    const headers = ExampleProtectedHeaders.create({ protectedHeaders: protectedHeaderMap })

    expect(payload).toBeInstanceOf(ExampleCwtPayload)
    expect(headers).toBeInstanceOf(ExampleProtectedHeaders)

    // `sub` is optional for a plain CWT but required here, and `profile` (65001) is required by
    // ExampleProtectedHeaders, so neither is accepted without it
    expect(() => ExampleCwtPayload.create({ issuer: 'coap://as.example' })).toThrow(/Subject \(2\)/)
    expect(() => ExampleProtectedHeaders.create({ protectedHeaders: new Map() })).toThrow(/Profile \(65001\)/)
  })

  test('should reject a payload missing a claim the cwt type requires', async () => {
    // `sub` is optional for a plain CWT, so this is a valid base payload but not a valid ExampleCwt one
    const cwt = Cwt.create({
      protectedHeaders: protectedHeaderMap,
      payload: CwtPayload.create({ issuer: 'coap://as.example' }),
    })
    const token = await cwt.signAndEncode({ signingKey: signKey, algorithm: SignatureAlgorithm.ES256 }, sign1Context)

    expect(() => Cwt.fromToken(token, { payload: CwtPayload })).not.toThrow()
    expect(() => ExampleCwt.fromToken(token)).toThrow(CwtPayloadDecodeError)
    // The inherited registered claim names survive the extension
    expect(() => ExampleCwt.fromToken(token)).toThrow(/Subject \(2\)/)
  })

  test('should name a claim the cwt type adds in a validation error', () => {
    expect(() =>
      exampleCwtPayloadSchema.parse(
        new Map<number, unknown>([
          [RegisteredCwtClaimKey.Subject, 'coap://light.example'],
          [ExampleClaimKey.Nickname, 42],
        ])
      )
    ).toThrow(/Nickname \(65000\)/)
  })

  test('should name a header label the cwt type adds in a validation error', () => {
    expect(() =>
      exampleProtectedHeaderClaims.parse(
        new Map<number, unknown>([
          [RegisteredCwtHeaderClaimKey.Algorithm, SignatureAlgorithm.ES256],
          [ExampleHeaderKey.Profile, 42],
        ])
      )
    ).toThrow(/Profile \(65001\)/)
  })

  test('should reject headers missing a label the cwt type requires', async () => {
    const payload = ExampleCwtPayload.fromDecodedStructure(
      exampleCwtPayloadSchema.parse(new Map<number, unknown>([[RegisteredCwtClaimKey.Subject, 'coap://light.example']]))
    )

    const missingProfile = () =>
      new ExampleCwt({
        // `profile` (65001) is required by ExampleProtectedHeaders but absent here
        protectedHeaders: ExampleProtectedHeaders.fromDecodedStructure(
          TypedMap.fromMap(
            new Map<number, unknown>([[RegisteredCwtHeaderClaimKey.Algorithm, SignatureAlgorithm.ES256]])
          )
        ),
        payload,
      })

    expect(missingProfile).toThrow(/ExampleProtectedHeaders/)
    expect(missingProfile).toThrow(/Profile \(65001\)/)
  })

  test('should not let an unprotected label satisfy a protected one the cwt type requires', async () => {
    const payload = ExampleCwtPayload.fromDecodedStructure(
      exampleCwtPayloadSchema.parse(new Map<number, unknown>([[RegisteredCwtClaimKey.Subject, 'coap://light.example']]))
    )

    expect(
      () =>
        new ExampleCwt({
          // `profile` (65001) is only integrity protected in the protected bucket, so an
          // unprotected copy — the one an attacker can write — must not satisfy the schema
          protectedHeaders: ExampleProtectedHeaders.fromDecodedStructure(
            TypedMap.fromMap(
              new Map<number, unknown>([[RegisteredCwtHeaderClaimKey.Algorithm, SignatureAlgorithm.ES256]])
            )
          ),
          unprotectedHeaders: new Map<number, unknown>([[ExampleHeaderKey.Profile, 'example']]),
          payload,
        })
    ).toThrow(/ExampleProtectedHeaders/)
  })
})
