import Crypto from 'node:crypto'
import { generateSalt, hasher } from '@owf/crypto'
import { describe, expect, test } from 'vitest'
import { createHashMapping, unpack } from '../decode'
import { Jwt } from '../jwt'
import { listKeys, pack, SdJwt } from '../sdjwt'
import type { DisclosureFrame, Signer } from '../types'
import { Disclosure } from '../utils'

const hash = { alg: 'SHA256', hasher }

describe('SD JWT', () => {
  test('create and encode', async () => {
    const { privateKey } = Crypto.generateKeyPairSync('ed25519')
    const testSigner: Signer = async (data: string) => {
      const sig = Crypto.sign(null, Buffer.from(data), privateKey)
      return Buffer.from(sig).toString('base64url')
    }

    const jwt = new Jwt({
      header: { alg: 'EdDSA' },
      payload: { foo: 'bar' },
    })

    await jwt.sign(testSigner)
    const sdJwt = new SdJwt({
      jwt,
      disclosures: [],
    })
    expect(sdJwt).toBeDefined()

    const encoded = sdJwt.encodeSdJwt()
    expect(encoded).toBeDefined()
  })

  test('decode', async () => {
    const { privateKey } = Crypto.generateKeyPairSync('ed25519')
    const testSigner: Signer = async (data: string) => {
      const sig = Crypto.sign(null, Buffer.from(data), privateKey)
      return Buffer.from(sig).toString('base64url')
    }

    const jwt = new Jwt({
      header: { alg: 'EdDSA' },
      payload: { foo: 'bar', _sd_alg: 'sha-256' },
    })

    await jwt.sign(testSigner)
    const sdJwt = new SdJwt({
      jwt,
      disclosures: [],
    })

    const encoded = sdJwt.encodeSdJwt()

    const newSdJwt = await SdJwt.fromEncode(encoded, hasher)
    expect(newSdJwt).toBeDefined()
    const newJwt = newSdJwt.jwt
    expect(newJwt?.header).toEqual(jwt.header)
    expect(newJwt?.payload).toEqual(jwt.payload)
    expect(newJwt?.signature).toEqual(jwt.signature)
  })

  test('decode compatibilty', async () => {
    const { privateKey } = Crypto.generateKeyPairSync('ed25519')
    const testSigner: Signer = async (data: string) => {
      const sig = Crypto.sign(null, Buffer.from(data), privateKey)
      return Buffer.from(sig).toString('base64url')
    }

    const jwt = new Jwt({
      header: { alg: 'EdDSA' },
      payload: { foo: 'bar' },
    })

    await jwt.sign(testSigner)
    const sdJwt = new SdJwt({
      jwt,
      disclosures: [],
    })

    const encoded = sdJwt.encodeSdJwt()

    const newSdJwt = await SdJwt.fromEncode(encoded, hasher)
    expect(newSdJwt).toBeDefined()
    const newJwt = newSdJwt.jwt
    expect(newJwt?.header).toEqual(jwt.header)
    expect(newJwt?.payload).toEqual(jwt.payload)
    expect(newJwt?.signature).toEqual(jwt.signature)
  })

  test('keys', async () => {
    const { privateKey } = Crypto.generateKeyPairSync('ed25519')
    const testSigner: Signer = async (data: string) => {
      const sig = Crypto.sign(null, Buffer.from(data), privateKey)
      return Buffer.from(sig).toString('base64url')
    }
    const jwt = new Jwt({
      header: { alg: 'EdDSA' },
      payload: { foo: 'bar' },
    })

    await jwt.sign(testSigner)
    const sdJwt = new SdJwt({
      jwt,
      disclosures: [],
    })

    const keys = await sdJwt.keys(hasher)
    expect(keys).toBeDefined()
    expect(keys).toEqual(['foo'])
  })

  test('presentable keys', async () => {
    const { privateKey } = Crypto.generateKeyPairSync('ed25519')
    const testSigner: Signer = async (data: string) => {
      const sig = Crypto.sign(null, Buffer.from(data), privateKey)
      return Buffer.from(sig).toString('base64url')
    }

    const jwt = new Jwt({
      header: { alg: 'EdDSA' },
      payload: { foo: 'bar' },
    })

    await jwt.sign(testSigner)
    const sdJwt = new SdJwt({
      jwt,
      disclosures: [],
    })

    const keys = await sdJwt.presentableKeys(hasher)
    expect(keys).toBeDefined()
    expect(keys).toEqual([])
  })

  test('claims', async () => {
    const { privateKey } = Crypto.generateKeyPairSync('ed25519')
    const testSigner: Signer = async (data: string) => {
      const sig = Crypto.sign(null, Buffer.from(data), privateKey)
      return Buffer.from(sig).toString('base64url')
    }

    const jwt = new Jwt({
      header: { alg: 'EdDSA' },
      payload: { foo: 'bar' },
    })

    await jwt.sign(testSigner)
    const sdJwt = new SdJwt({
      jwt,
      disclosures: [],
    })

    const claims = await sdJwt.getClaims(hasher)
    expect(claims).toBeDefined()
    expect(claims).toEqual({
      foo: 'bar',
    })
  })

  test('pack', async () => {
    const claim = {
      firstname: 'John',
      lastname: 'Doe',
    }

    const { packedClaims, disclosures } = await pack(
      claim,
      {
        _sd: ['firstname'],
      },
      hash,
      generateSalt
    )

    expect(disclosures).toBeDefined()
    expect(packedClaims).toBeDefined()

    expect(disclosures.length).toEqual(1)
    expect(disclosures[0].key).toEqual('firstname')
    expect(disclosures[0].value).toEqual('John')

    const packedObject = packedClaims as Record<string, any>
    expect(packedObject._sd).toBeDefined()
    expect(packedObject._sd.length).toEqual(1)
    expect(packedObject.lastname).toEqual('Doe')
  })

  test('list keys', () => {
    const data = {
      a: {
        b: {
          c: 1,
        },
        d: [
          {
            e: 'fasfdsa',
            f: 1234,
          },
          3,
          4,
        ],
      },
      g: [['h'], 'i'],
    }

    const keys = listKeys(data)
    expect(keys).toEqual([
      'a',
      'a.b',
      'a.b.c',
      'a.d',
      'a.d.0',
      'a.d.0.e',
      'a.d.0.f',
      'a.d.1',
      'a.d.2',
      'g',
      'g.0',
      'g.0.0',
      'g.1',
    ])
  })

  test('presentable keys', async () => {
    const claim = {
      firstname: 'John',
      lastname: 'Doe',
    }

    const { packedClaims, disclosures } = await pack(
      claim,
      {
        _sd: ['firstname'],
      },
      hash,
      generateSalt
    )

    const { privateKey } = Crypto.generateKeyPairSync('ed25519')
    const testSigner: Signer = async (data: string) => {
      const sig = Crypto.sign(null, Buffer.from(data), privateKey)
      return Buffer.from(sig).toString('base64url')
    }
    const jwt = new Jwt({
      header: { alg: 'EdDSA' },
      payload: packedClaims as Record<string, unknown>,
    })

    await jwt.sign(testSigner)
    const sdJwt = new SdJwt({
      jwt,
      disclosures,
    })

    const keys = await sdJwt.presentableKeys(hasher)

    expect(keys).toBeDefined()
    expect(keys).toEqual(['firstname'])
  })

  test('hash map', async () => {
    const claim = {
      firstname: 'John',
      lastname: 'Doe',
    }

    const { disclosures } = await pack(
      claim,
      {
        _sd: ['firstname'],
      },
      hash,
      generateSalt
    )

    const mapping = await createHashMapping(disclosures, hash)
    expect(mapping).toBeDefined()
    expect(Object.keys(mapping).length).toEqual(1)
    expect(mapping[Object.keys(mapping)[0]]).toBeInstanceOf(Disclosure)
  })

  test('unpack', async () => {
    const claim = {
      firstname: 'John',
      lastname: 'Doe',
    }

    const { packedClaims, disclosures } = await pack(
      claim,
      {
        _sd: ['firstname'],
      },
      hash,
      generateSalt
    )

    const { disclosureKeymap, unpackedObj } = await unpack(packedClaims as Record<string, unknown>, disclosures, hasher)
    expect(disclosureKeymap).toBeDefined()
    expect(unpackedObj).toBeDefined()
    expect(unpackedObj).toEqual({
      firstname: 'John',
      lastname: 'Doe',
    })
    expect(disclosureKeymap.firstname).toBeDefined()
    expect(typeof disclosureKeymap.firstname).toEqual('string')
  })

  test('pack and unpack', async () => {
    const claims = {
      firstname: 'John',
      lastname: 'Doe',
      ssn: '123-45-6789',
      id: '1234',
      data: {
        firstname: 'John',
        lastname: 'Doe',
        ssn: '123-45-6789',
        list: [{ r: '1' }, 'b', 'c'],
      },
      data2: {
        hi: 'bye',
      },
    }

    const disclosureFrame: DisclosureFrame<typeof claims> = {
      _sd: ['firstname', 'id', 'data2'],
      data: {
        _sd: ['list'],
        _sd_decoy: 2,
        list: {
          _sd: [0, 2],
          _sd_decoy: 1,
          0: {
            _sd: ['r'],
          },
        },
      },
      data2: {
        _sd: ['hi'],
      },
    }

    const { packedClaims, disclosures } = await pack(claims, disclosureFrame, hash, generateSalt)
    const { unpackedObj } = await unpack(packedClaims as Record<string, unknown>, disclosures, hasher)

    expect(unpackedObj).toEqual(claims)
  })

  test('no disclosures', async () => {
    const { privateKey } = Crypto.generateKeyPairSync('ed25519')
    const testSigner: Signer = async (data: string) => {
      const sig = Crypto.sign(null, Buffer.from(data), privateKey)
      return Buffer.from(sig).toString('base64url')
    }

    const jwt = new Jwt({
      header: { alg: 'EdDSA' },
      payload: { foo: 'bar' },
    })

    await jwt.sign(testSigner)
    const sdJwt = new SdJwt({
      jwt,
      disclosures: [],
    })

    const credential = sdJwt.encodeSdJwt()
    const decoded = await SdJwt.decodeSdJwt(credential, hasher)
    expect(jwt.header).toEqual(decoded.jwt.header)
    expect(jwt.payload).toEqual(decoded.jwt.payload)
    expect(jwt.signature).toEqual(decoded.jwt.signature)
    expect(decoded.disclosures).toEqual([])
  })

  test('nested disclosures are not mutated during unpack (issue #264)', async () => {
    const claims = {
      iss: 'issuer',
      address: {
        geo: {
          lat: 1,
        },
      },
    }
    const disclosureFrame: DisclosureFrame<typeof claims> = {
      _sd: ['address'],
      address: {
        geo: {
          _sd: ['lat'],
        },
      },
    }

    const { packedClaims, disclosures } = await pack(claims, disclosureFrame, hash, generateSalt)
    const { privateKey } = Crypto.generateKeyPairSync('ed25519')
    const testSigner: Signer = async (data: string) => {
      const sig = Crypto.sign(null, Buffer.from(data), privateKey)
      return Buffer.from(sig).toString('base64url')
    }

    const jwt = new Jwt({
      header: { alg: 'EdDSA' },
      payload: { ...(packedClaims as Record<string, unknown>), _sd_alg: 'sha-256' },
    })
    await jwt.sign(testSigner)
    const sdJwt = new SdJwt({ jwt, disclosures })
    const compact = sdJwt.encodeSdJwt()

    const decoded = await SdJwt.fromEncode(compact, hasher)
    const claims1 = await decoded.getClaims(hasher)
    expect(claims1).toEqual(claims)

    // Second call to getClaims on the same decoded instance must not throw
    const claims2 = await decoded.getClaims(hasher)
    expect(claims2).toEqual(claims)
  })

  test('nested array disclosures are not mutated during unpack (issue #264)', async () => {
    const claims = {
      iss: 'issuer',
      list: [
        {
          item: 'first',
        },
      ],
    }
    const disclosureFrame: DisclosureFrame<typeof claims> = {
      _sd: ['list'],
      list: {
        _sd: [0],
        0: {
          _sd: ['item'],
        },
      },
    }

    const { packedClaims, disclosures } = await pack(claims, disclosureFrame, hash, generateSalt)
    const { privateKey } = Crypto.generateKeyPairSync('ed25519')
    const testSigner: Signer = async (data: string) => {
      const sig = Crypto.sign(null, Buffer.from(data), privateKey)
      return Buffer.from(sig).toString('base64url')
    }

    const jwt = new Jwt({
      header: { alg: 'EdDSA' },
      payload: { ...(packedClaims as Record<string, unknown>), _sd_alg: 'sha-256' },
    })
    await jwt.sign(testSigner)
    const sdJwt = new SdJwt({ jwt, disclosures })
    const compact = sdJwt.encodeSdJwt()

    const decoded = await SdJwt.fromEncode(compact, hasher)
    const claims1 = await decoded.getClaims(hasher)
    expect(claims1).toEqual(claims)

    const claims2 = await decoded.getClaims(hasher)
    expect(claims2).toEqual(claims)
  })
})
