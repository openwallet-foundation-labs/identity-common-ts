import { CoseKey, KeyType, type Mac0Context, type Sign1, type Sign1Context, SignatureAlgorithm } from '@owf/cose'
import { expect, suite, test } from 'vitest'
import { StatusListCbor } from '../../cbor/status-list-cbor'
import { StatusListCwt, StatusListCwtHeaderKey } from '../../cbor/status-list-cwt'
import { StatusListCwtPayload } from '../../cbor/status-list-cwt-payload'
import { StatusList } from '../../status-list'
import { StatusTypes } from '../../types'

const sign1Context: Sign1Context = {
  sign: async (_options: {
    toBeSigned: Uint8Array
    key: CoseKey
    algorithm: SignatureAlgorithm
  }): Promise<Uint8Array> => new Uint8Array([1, 2, 3]),
  verify: async (_options: { sign1: Sign1; key: Uint8Array | CoseKey }): Promise<boolean> => true,
  x509: {
    getIssuerNameField: (_options: { certificate: Uint8Array | Uint8Array[]; field: string }): string[] => ['a', 'v'],
    getPublicKey: async (_options: { certificate: Uint8Array | Uint8Array[]; alg: string }): Promise<Uint8Array> =>
      new Uint8Array([7, 8, 9]),
  },
}

const mac0Context: Mac0Context = {
  mac: async (_options: { toBeAuthenticated: Uint8Array; key: CoseKey | Uint8Array }): Promise<Uint8Array> =>
    new Uint8Array([4, 5, 6]),
}

const key = CoseKey.fromJwk({
  kty: 'EC',
  crv: 'P-256',
  x: 'usWxHK2PmfnHKwXPS54m0kTcGJ90UiglWiGahtagnv8',
  y: 'IBOL-C3BttVivg-lSreASjpkttcsz-1rb7btKLv8EX4',
  d: 'V8kgd2ZBRuh2dgyVINBUqpPDr7BOMGcF22CQMIUHtNM',
})

suite('StatusListCwt', () => {
  suite('constructor', () => {
    test('should create with payload as StatusListCwtPayload', () => {
      const payload = StatusListCwtPayload.create({
        subject: 'did:test',
        statusList: new StatusList([0, 1, 0, 0], 4),
      })
      const cwt = new StatusListCwt({ payload })
      expect(cwt).toBeInstanceOf(StatusListCwt)
    })

    test('should create with payload as CreateStatusListCwtPayloadOptions', () => {
      const cwt = new StatusListCwt({
        payload: {
          subject: 'did:test',
          statusList: new StatusList([0, 1, 0], 1),
        },
      })
      expect(cwt).toBeInstanceOf(StatusListCwt)
    })

    test('should set Typ header to STATUS_LIST_CWT by default', () => {
      const cwt = new StatusListCwt({
        payload: {
          subject: 'did:test',
          statusList: new StatusList([0, 1, 0], 1),
        },
      })
      expect(cwt.protectedHeaders?.headers.get(StatusListCwtHeaderKey.Typ)).toBe('application/statuslist+cwt')
    })

    test('should allow custom protected headers', () => {
      const protectedHeaders = new Map<number, unknown>([[1, 123]])
      const cwt = new StatusListCwt({
        payload: {
          subject: 'did:test',
          statusList: new StatusList([0, 1, 0], 1),
        },
        protectedHeaders,
      })
      expect(cwt.protectedHeaders?.headers.get(1)).toBe(123)
      expect(cwt.protectedHeaders?.headers.get(StatusListCwtHeaderKey.Typ)).toBe('application/statuslist+cwt')
    })

    test('should allow custom unprotected headers', () => {
      const unprotectedHeaders = new Map<number, unknown>([[10, 'test']])
      const cwt = new StatusListCwt({
        payload: {
          subject: 'did:test',
          statusList: new StatusList([0, 1, 0], 1),
        },
        unprotectedHeaders,
      })
      expect(cwt.unprotectedHeaders?.headers.get(10)).toBe('test')
    })
  })

  suite('createFromStatusListAndSubject', () => {
    test('should create with StatusList instance', () => {
      const statusList = new StatusList([0, 1, 0], 1)
      const cwt = StatusListCwt.createFromStatusListAndSubject(statusList, 'did:test')
      expect(cwt).toBeInstanceOf(StatusListCwt)
    })

    test('should create with CborStatusList instance', () => {
      const cborStatusList = StatusListCbor.create({ bits: 1, list: [0, 1, 0] })
      const cwt = StatusListCwt.createFromStatusListAndSubject(cborStatusList, 'did:test')
      expect(cwt).toBeInstanceOf(StatusListCwt)
    })

    test('should create with plain object', () => {
      const cwt = StatusListCwt.createFromStatusListAndSubject(
        { statusList: [0, 1, 0], bitsPerStatus: 1, aggregationUri: 'https://example.com' },
        'did:test'
      )
      expect(cwt).toBeInstanceOf(StatusListCwt)
    })

    test('should create with aggregationUri', () => {
      const cwt = StatusListCwt.createFromStatusListAndSubject(
        { statusList: [0, 1, 0], bitsPerStatus: 1, aggregationUri: 'https://example.com/list' },
        'did:test'
      )
      expect(cwt).toBeInstanceOf(StatusListCwt)
    })
  })

  suite('setStatusList', () => {
    test('should update status list with StatusList instance', () => {
      const cwt = StatusListCwt.createFromStatusListAndSubject({ statusList: [0, 0, 0], bitsPerStatus: 1 }, 'did:test')
      const newStatusList = new StatusList([1, 1, 1], 1)
      cwt.setStatusList(newStatusList)
      // Get the first 3 statuses (compression may add padding)
      const result = cwt.payload.statusList.statusList.slice(0, 3)
      expect(result).toEqual([1, 1, 1])
    })

    test('should update status list with CborStatusList instance', () => {
      const cwt = StatusListCwt.createFromStatusListAndSubject({ statusList: [0, 0, 0], bitsPerStatus: 1 }, 'did:test')
      const newCborStatusList = StatusListCbor.create({ bits: 1, list: [1, 1, 1] })
      cwt.setStatusList(newCborStatusList)
      // Get the first 3 statuses (compression may add padding)
      const result = cwt.payload.statusList.statusList.slice(0, 3)
      expect(result).toEqual([1, 1, 1])
    })
  })

  suite('updateStatusList', () => {
    test('should update status at specific index', () => {
      const cwt = StatusListCwt.createFromStatusListAndSubject({ statusList: [0, 0, 0], bitsPerStatus: 1 }, 'did:test')
      cwt.updateStatusList(1, 1)
      expect(cwt.payload.statusList.getStatus(1)).toBe(1)
    })

    test('should throw error for out of bounds index', () => {
      const cwt = StatusListCwt.createFromStatusListAndSubject({ statusList: [0, 0, 0], bitsPerStatus: 1 }, 'did:test')
      expect(() => cwt.updateStatusList(10, 1)).toThrow('Index out of bounds')
    })
  })

  suite('encode/decode with sign1', () => {
    test('encode/decode with sign1', async () => {
      const statusListCwt = StatusListCwt.createFromStatusListAndSubject(
        { statusList: [0, 0, 0], bitsPerStatus: 8 },
        'did:you'
      )

      const token = await statusListCwt.signAndEncode(
        { signingKey: key, algorithm: SignatureAlgorithm.ES256 },
        sign1Context
      )

      const decodedStatusListCwt = StatusListCwt.fromToken(token)
      expect(decodedStatusListCwt).toMatchObject(statusListCwt)
    })

    test('encode/decode with different status values', async () => {
      const statusListCwt = StatusListCwt.createFromStatusListAndSubject(
        { statusList: [StatusTypes.VALID, StatusTypes.INVALID, StatusTypes.SUSPENDED], bitsPerStatus: 2 },
        'did:you'
      )

      const token = await statusListCwt.signAndEncode(
        { signingKey: key, algorithm: SignatureAlgorithm.ES256 },
        sign1Context
      )

      const decodedStatusListCwt = StatusListCwt.fromToken(token)
      const result = decodedStatusListCwt.payload.statusList.statusList.slice(0, 3)
      expect(result).toEqual([StatusTypes.VALID, StatusTypes.INVALID, StatusTypes.SUSPENDED])
    })

    test('encode/decode with bitsPerStatus=4', async () => {
      const statusListCwt = StatusListCwt.createFromStatusListAndSubject(
        { statusList: [0, 1, 2, 3, 4], bitsPerStatus: 4 },
        'did:you'
      )

      const token = await statusListCwt.signAndEncode(
        { signingKey: key, algorithm: SignatureAlgorithm.ES256 },
        sign1Context
      )

      const decodedStatusListCwt = StatusListCwt.fromToken(token)
      const result = decodedStatusListCwt.payload.statusList.statusList.slice(0, 5)
      expect(result).toEqual([0, 1, 2, 3, 4])
    })

    test('encode/decode with bitsPerStatus=8', async () => {
      const statusListCwt = StatusListCwt.createFromStatusListAndSubject(
        { statusList: [0, 10, 20, 255], bitsPerStatus: 8 },
        'did:you'
      )

      const token = await statusListCwt.signAndEncode(
        { signingKey: key, algorithm: SignatureAlgorithm.ES256 },
        sign1Context
      )

      const decodedStatusListCwt = StatusListCwt.fromToken(token)
      const result = decodedStatusListCwt.payload.statusList.statusList.slice(0, 4)
      expect(result).toEqual([0, 10, 20, 255])
    })

    test('encode/decode with aggregationUri', async () => {
      const aggregationUri = 'https://example.com/status-list'
      const statusListCwt = StatusListCwt.createFromStatusListAndSubject(
        { statusList: [0, 1, 0], bitsPerStatus: 1, aggregationUri },
        'did:you'
      )

      const token = await statusListCwt.signAndEncode(
        { signingKey: key, algorithm: SignatureAlgorithm.ES256 },
        sign1Context
      )

      const decodedStatusListCwt = StatusListCwt.fromToken(token)
      expect(decodedStatusListCwt.payload.statusList.aggregationUri).toStrictEqual(aggregationUri)
    })

    test('encode/decode with custom issuedAt', async () => {
      const issuedAt = new Date(Math.floor(Date.now() / 1000) * 1000)
      const statusListCwt = new StatusListCwt({
        payload: {
          subject: 'did:test',
          statusList: new StatusList([0, 1, 0], 1),
          issuedAt,
        },
      })

      const token = await statusListCwt.signAndEncode(
        { signingKey: key, algorithm: SignatureAlgorithm.ES256 },
        sign1Context
      )

      const decodedStatusListCwt = StatusListCwt.fromToken(token)
      const decodedIssuedAt = decodedStatusListCwt.payload.issuedAt
      expect(decodedIssuedAt).toStrictEqual(issuedAt)
    })

    test('encode/decode with expirationTime', async () => {
      const expirationTime = new Date(Math.floor(Date.now() / 1000) * 1000)
      const statusListCwt = new StatusListCwt({
        payload: {
          subject: 'did:test',
          statusList: new StatusList([0, 1, 0], 1),
          expirationTime,
        },
      })

      const token = await statusListCwt.signAndEncode(
        { signingKey: key, algorithm: SignatureAlgorithm.ES256 },
        sign1Context
      )

      const decodedStatusListCwt = StatusListCwt.fromToken(token)
      const decodedExpirationTime = decodedStatusListCwt.payload.expirationTime
      expect(decodedExpirationTime).toStrictEqual(expirationTime)
    })

    test('encode/decode with timeToLive', async () => {
      const timeToLive = 3600
      const statusListCwt = new StatusListCwt({
        payload: {
          subject: 'did:test',
          statusList: new StatusList([0, 1, 0], 1),
          timeToLive,
        },
      })

      const token = await statusListCwt.signAndEncode(
        { signingKey: key, algorithm: SignatureAlgorithm.ES256 },
        sign1Context
      )

      const decodedStatusListCwt = StatusListCwt.fromToken(token)
      expect(decodedStatusListCwt.payload.timeToLive).toBe(timeToLive)
    })
  })

  suite('encode/decode with mac0', () => {
    test('encode/decode with mac0', async () => {
      const statusListCwt = StatusListCwt.createFromStatusListAndSubject(
        { statusList: [0, 0, 0], bitsPerStatus: 8 },
        'did:you'
      )

      const token = await statusListCwt.authenticateAndEncode(
        { key: CoseKey.create({ keyType: KeyType.Ec }) },
        mac0Context
      )

      const decodedStatusListCwt = StatusListCwt.fromToken(token)
      expect(decodedStatusListCwt).toMatchObject(statusListCwt)
    })

    test('encode/decode with mac0 and custom headers', async () => {
      const protectedHeaders = new Map<number, unknown>([[1, 123]])
      const unprotectedHeaders = new Map<number, unknown>([[10, 'test']])
      const statusListCwt = new StatusListCwt({
        payload: {
          subject: 'did:test',
          statusList: new StatusList([0, 1, 0], 1),
        },
        protectedHeaders,
        unprotectedHeaders,
      })

      const token = await statusListCwt.authenticateAndEncode(
        { key: CoseKey.create({ keyType: KeyType.Ec }) },
        mac0Context
      )

      const decodedStatusListCwt = StatusListCwt.fromToken(token)
      expect(decodedStatusListCwt.protectedHeaders?.headers.get(1)).toBe(123)
      expect(decodedStatusListCwt.unprotectedHeaders?.headers.get(10)).toBe('test')
    })
  })

  suite('fromToken', () => {
    test('should decode sign1 token correctly', async () => {
      const original = StatusListCwt.createFromStatusListAndSubject(
        { statusList: [1, 0, 1], bitsPerStatus: 1 },
        'did:issuer'
      )
      const token = await original.signAndEncode({ signingKey: key, algorithm: SignatureAlgorithm.ES256 }, sign1Context)

      const decoded = StatusListCwt.fromToken(token)
      const result = decoded.payload.statusList.statusList.slice(0, 3)
      expect(result).toEqual([1, 0, 1])
      expect(decoded.payload.subject).toBe('did:issuer') // Subject
    })

    test('should decode mac0 token correctly', async () => {
      const original = StatusListCwt.createFromStatusListAndSubject(
        { statusList: [1, 0, 1], bitsPerStatus: 1 },
        'did:issuer'
      )
      const token = await original.authenticateAndEncode({ key: CoseKey.create({ keyType: KeyType.Ec }) }, mac0Context)

      const decoded = StatusListCwt.fromToken(token)
      const result = decoded.payload.statusList.statusList.slice(0, 3)
      expect(result).toEqual([1, 0, 1])
      expect(decoded.payload.subject).toBe('did:issuer')
    })

    test('should preserve Typ header after round-trip', async () => {
      const original = StatusListCwt.createFromStatusListAndSubject(
        { statusList: [0, 0, 0], bitsPerStatus: 1 },
        'did:test'
      )
      const token = await original.signAndEncode({ signingKey: key, algorithm: SignatureAlgorithm.ES256 }, sign1Context)

      const decoded = StatusListCwt.fromToken(token)
      expect(decoded.protectedHeaders?.headers.get(StatusListCwtHeaderKey.Typ)).toBe('application/statuslist+cwt')
    })
  })

  suite('large status lists', () => {
    test('encode/decode with large status list (100 entries)', async () => {
      const statusList = Array(100)
        .fill(0)
        .map((_, i) => i % 2)
      const statusListCwt = StatusListCwt.createFromStatusListAndSubject({ statusList, bitsPerStatus: 1 }, 'did:you')

      const token = await statusListCwt.signAndEncode(
        { signingKey: key, algorithm: SignatureAlgorithm.ES256 },
        sign1Context
      )

      const decodedStatusListCwt = StatusListCwt.fromToken(token)
      expect(decodedStatusListCwt.payload.statusList.statusList.slice(0, 100)).toEqual(statusList)
    })

    test('encode/decode with large status list (1000 entries)', async () => {
      const statusList = Array(1000).fill(StatusTypes.VALID)
      const statusListCwt = StatusListCwt.createFromStatusListAndSubject({ statusList, bitsPerStatus: 2 }, 'did:you')

      const token = await statusListCwt.signAndEncode(
        { signingKey: key, algorithm: SignatureAlgorithm.ES256 },
        sign1Context
      )

      const decodedStatusListCwt = StatusListCwt.fromToken(token)
      expect(decodedStatusListCwt.payload.statusList.statusList.length).toBeGreaterThanOrEqual(1000)
      expect(decodedStatusListCwt.payload.statusList.statusList[0]).toBe(StatusTypes.VALID)
    })
  })

  suite('status modification after encoding', () => {
    test('should modify status and re-encode correctly', async () => {
      const statusListCwt = StatusListCwt.createFromStatusListAndSubject(
        { statusList: [0, 0, 0], bitsPerStatus: 1 },
        'did:you'
      )

      // Modify status before encoding
      statusListCwt.updateStatusList(1, 1)

      const token = await statusListCwt.signAndEncode(
        { signingKey: key, algorithm: SignatureAlgorithm.ES256 },
        sign1Context
      )

      const decodedStatusListCwt = StatusListCwt.fromToken(token)
      expect(decodedStatusListCwt.payload.statusList.getStatus(1)).toBe(1)
    })

    test('should replace entire status list and re-encode correctly', async () => {
      const statusListCwt = StatusListCwt.createFromStatusListAndSubject(
        { statusList: [0, 0, 0], bitsPerStatus: 1 },
        'did:you'
      )

      // Replace entire status list
      statusListCwt.setStatusList(new StatusList([1, 1, 1], 1))

      const token = await statusListCwt.signAndEncode(
        { signingKey: key, algorithm: SignatureAlgorithm.ES256 },
        sign1Context
      )

      const decodedStatusListCwt = StatusListCwt.fromToken(token)
      const result = decodedStatusListCwt.payload.statusList.statusList.slice(0, 3)
      expect(result).toEqual([1, 1, 1])
    })
  })
})
