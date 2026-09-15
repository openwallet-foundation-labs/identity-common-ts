import { cborDecode, cborEncode } from '@owf/cose'
import { hex } from '@owf/identity-common'
import { describe, expect, test } from 'vitest'
import { DeviceEngagement } from '../../mdoc/models/device-engagement'
import { Oidc } from '../../mdoc/models/oidc'
import { Security } from '../../mdoc/models/security'
import { ServerRetrievalMethod } from '../../mdoc/models/server-retrieval-method'

const cbor =
  'a30063312e30018201d818584ba4010220012158205a88d182bce5f42efa59943f33359d2e8a968ff289d93e5fa444b624343167fe225820b16e8cf858ddc7690407ba61d4c338237a8cfcf3de6aa672fc60a557aa32fc670281830201a300f401f50b5045efef742b2c4837a9a3b0e1d05a6917'

describe('device engagement', () => {
  test('parse', () => {
    const deviceEngagement = DeviceEngagement.decode(hex.decode(cbor))

    expect(deviceEngagement.version).toStrictEqual('1.0')
    expect(deviceEngagement.security).toBeInstanceOf(Security)
    expect(deviceEngagement.deviceRetrievalMethods).toBeDefined()
  })
})

describe('device engagement server retrieval methods (18013-5 8.2.1.1)', () => {
  // The device engagement above with ServerRetrievalMethods = { "webApi": [1, URL, token] } under key 3.
  const withServerRetrieval = (() => {
    const deviceEngagement = cborDecode(hex.decode(cbor)) as Map<number, unknown>
    deviceEngagement.set(3, new Map([['webApi', [1, 'https://issuer.example.com/mdl', 'token']]]))
    return cborEncode(deviceEngagement)
  })()

  test('parse a single ServerRetrievalMethods map', () => {
    const deviceEngagement = DeviceEngagement.decode(withServerRetrieval)

    expect(deviceEngagement.serverRetrievalMethods?.webApi?.issuerUrl).toStrictEqual('https://issuer.example.com/mdl')
    expect(deviceEngagement.serverRetrievalMethods?.oidc).toBeUndefined()
    expect(hex.encode(deviceEngagement.encode())).toStrictEqual(hex.encode(withServerRetrieval))
  })

  test('create with a ServerRetrievalMethods map', () => {
    const decoded = DeviceEngagement.decode(withServerRetrieval)

    const deviceEngagement = DeviceEngagement.create({
      version: '1.0',
      security: decoded.security,
      serverRetrievalMethods: ServerRetrievalMethod.create({
        oidc: Oidc.create({ version: 1, issuerUrl: 'https://issuer.example.com', serverRetrievalToken: 'token' }),
      }),
    })

    const encoded = cborDecode(deviceEngagement.encode()) as Map<number, unknown>
    expect(encoded.get(3)).toStrictEqual(new Map([['oidc', [1, 'https://issuer.example.com', 'token']]]))
  })
})
