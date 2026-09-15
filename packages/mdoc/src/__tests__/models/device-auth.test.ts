import { cborEncode } from '@owf/cose'
import { hex } from '@owf/identity-common'
import { describe, expect, test } from 'vitest'
import { DeviceAuth, DeviceMac, DeviceSignature } from '../..'

const cbor = 'a1696465766963654d61638443a10105a0f65820e99521a85ad7891b806a07f8b5388a332d92c189a7bf293ee1f543405ae6824d'

const deviceMac = () => DeviceAuth.decode(hex.decode(cbor)).deviceMac as DeviceMac

// COSE_Sign1 with alg ES256 and a detached payload. The signature is not verified when decoding.
const deviceSignature = () =>
  DeviceSignature.fromEncodedStructure([hex.decode('a10126'), new Map(), null, new Uint8Array(64)])

describe('device auth', () => {
  test('parse', () => {
    const deviceAuth = DeviceAuth.decode(hex.decode(cbor))

    expect(deviceAuth.deviceMac).toBeInstanceOf(DeviceMac)
    expect(deviceAuth.deviceSignature).toBeUndefined()
  })

  test('decoding fails when both deviceSignature and deviceMac are present', () => {
    const bytes = cborEncode(
      new Map<string, unknown>([
        ['deviceSignature', deviceSignature().encodedStructure],
        ['deviceMac', deviceMac().encodedStructure],
      ])
    )

    expect(() => DeviceAuth.decode(bytes)).toThrow('not both or neither')
  })

  test('decoding fails when neither deviceSignature nor deviceMac is present', () => {
    expect(() => DeviceAuth.decode(cborEncode(new Map()))).toThrow('not both or neither')
  })

  test('creating fails when both deviceSignature and deviceMac are provided', () => {
    expect(() => DeviceAuth.create({ deviceSignature: deviceSignature(), deviceMac: deviceMac() })).toThrow(
      'not both or neither'
    )
  })

  test('creating fails when neither deviceSignature nor deviceMac is provided', () => {
    expect(() => DeviceAuth.create({})).toThrow('not both or neither')
  })

  test('creating succeeds with only a deviceSignature', () => {
    expect(DeviceAuth.create({ deviceSignature: deviceSignature() }).deviceSignature).toBeInstanceOf(DeviceSignature)
  })
})
