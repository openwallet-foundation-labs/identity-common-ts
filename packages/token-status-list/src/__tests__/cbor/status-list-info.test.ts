import { cborDecode } from '@owf/cose'
import { ValidationError } from '@owf/identity-common'
import { describe, expect, test } from 'vitest'
import { StatusListInfo } from '../../cbor/status-list-info'

const uri = 'https://example.com/statuslists/1'

describe('StatusListInfo', () => {
  test('encodes and decodes the uri and idx of the status list entry', () => {
    const decoded = StatusListInfo.decode(StatusListInfo.create({ uri, idx: 42 }).encode())

    expect([decoded.uri, decoded.idx]).toEqual([uri, 42])
  })

  test('encodes and decodes a certificate', () => {
    const certificate = new Uint8Array([0x30, 0x82, 0x01, 0x0a])

    const decoded = StatusListInfo.decode(StatusListInfo.create({ uri, idx: 42, certificate }).encode())

    expect(decoded.certificate).toEqual(certificate)
  })

  test('leaves out the certificate when there is none', () => {
    const encoded = cborDecode<Map<string, unknown>>(StatusListInfo.create({ uri, idx: 42 }).encode())

    expect([...encoded.keys()]).toEqual(['uri', 'idx'])
  })

  test.each([
    ['negative', -1],
    ['fractional', 1.5],
  ])('rejects a %s idx', (_name, idx) => {
    expect(() => StatusListInfo.create({ uri, idx })).toThrow(ValidationError)
  })
})
