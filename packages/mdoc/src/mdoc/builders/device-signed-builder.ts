import {
  type CoseKey,
  MacAlgorithm,
  ProtectedHeaders,
  RegisteredCwtHeaderClaimKey,
  type SignatureAlgorithm,
  UnprotectedHeaders,
} from '@owf/cose'
import { stringToBytes } from '@owf/identity-common'
import type { MdocContext } from '../../context'
import { UnsupportedDeviceMacAlgorithmError } from '../errors'
import {
  DeviceAuth,
  DeviceMac,
  DeviceNamespaces,
  DeviceSignature,
  DeviceSigned,
  DeviceSignedItems,
  type DocType,
  type Namespace,
  type SessionTranscript,
} from '../models'
import { DeviceAuthentication } from '../models/device-authentication'

export class DeviceSignedBuilder {
  private docType: DocType
  private namespaces: DeviceNamespaces
  private ctx: Pick<MdocContext, 'cose' | 'crypto'>

  public constructor(docType: DocType, ctx: Pick<MdocContext, 'cose' | 'crypto'>) {
    this.docType = docType
    this.namespaces = DeviceNamespaces.create({ deviceNamespaces: new Map() })
    this.ctx = ctx
  }

  public addDeviceNamespace(namespace: Namespace, value: Record<string, unknown>) {
    if (!this.namespaces.getDeviceNamespace(namespace)) {
      this.namespaces.setDeviceNamespace(namespace, DeviceSignedItems.create({ deviceSignedItems: new Map() }))
    }

    for (const [elementIdentifier, elementValue] of Object.entries(value)) {
      this.namespaces.setDeviceSignedElement(namespace, elementIdentifier, elementValue)
    }

    return this
  }

  public async sign(options: {
    signingKey: CoseKey
    algorithm: SignatureAlgorithm
    sessionTranscript: SessionTranscript
  }): Promise<DeviceSigned> {
    const protectedHeaders = ProtectedHeaders.create({
      protectedHeaders: new Map([[RegisteredCwtHeaderClaimKey.Algorithm, options.algorithm]]),
    })

    const unprotectedHeaders = UnprotectedHeaders.create({})

    if (options.signingKey.keyId) {
      // COSE label 4 (kid) is a bstr per RFC 8152; UTF-8 encode the
      // text form at the header boundary.
      unprotectedHeaders.headers?.set(RegisteredCwtHeaderClaimKey.KeyId, stringToBytes(options.signingKey.keyId))
    }

    const deviceAuthentication = DeviceAuthentication.create({
      sessionTranscript: options.sessionTranscript,
      deviceNamespaces: this.namespaces,
      docType: this.docType,
    })

    const deviceSignature = DeviceSignature.create({
      unprotectedHeaders,
      protectedHeaders,
      payload: null,
    })

    await deviceSignature.sign(
      {
        signingKey: options.signingKey,
        detachedPayload: deviceAuthentication.encode({ asDataItem: true }),
      },
      { sign: this.ctx.cose.sign1.sign }
    )

    return DeviceSigned.create({
      deviceNamespaces: this.namespaces,
      deviceAuth: DeviceAuth.create({
        deviceSignature,
      }),
    })
  }

  public async tag(options: {
    publicKey: CoseKey
    privateKey: CoseKey
    sessionTranscript: SessionTranscript
    algorithm: MacAlgorithm
  }): Promise<DeviceSigned> {
    // 18013-5 9.1.3.5: the device MAC shall use HMAC 256/256, which `DeviceAuth.verify` enforces.
    if (options.algorithm !== MacAlgorithm.HS256) {
      throw new UnsupportedDeviceMacAlgorithmError(
        `Device MAC algorithm must be HMAC 256/256 (${MacAlgorithm.HS256}), received ${options.algorithm}`
      )
    }

    const protectedHeaders = ProtectedHeaders.create({
      protectedHeaders: new Map<number, unknown>([[RegisteredCwtHeaderClaimKey.Algorithm, options.algorithm]]),
    })

    const unprotectedHeaders = UnprotectedHeaders.create({})

    if (options.privateKey.keyId) {
      // COSE label 4 (kid) is a bstr per RFC 8152; UTF-8 encode the
      // text form at the header boundary.
      unprotectedHeaders.headers?.set(RegisteredCwtHeaderClaimKey.KeyId, stringToBytes(options.privateKey.keyId))
    }

    const deviceAuthentication = DeviceAuthentication.create({
      sessionTranscript: options.sessionTranscript,
      deviceNamespaces: this.namespaces,
      docType: this.docType,
    })

    const deviceMac = DeviceMac.create({
      unprotectedHeaders,
      protectedHeaders,
      payload: null,
    })

    const derivedKey = await deviceMac.createDeviceMacKey(
      {
        privateKey: options.privateKey,
        publicKey: options.publicKey,
        sessionTranscript: options.sessionTranscript,
        info: 'EMacKey',
      },
      this.ctx
    )

    const deviceMacWithTag = await deviceMac.authenticate(
      {
        key: derivedKey,
        algorithm: options.algorithm,
        detachedPayload: deviceAuthentication.encode({ asDataItem: true }),
      },
      this.ctx.cose.mac0
    )

    return DeviceSigned.create({
      deviceNamespaces: this.namespaces,
      deviceAuth: DeviceAuth.create({
        deviceMac: deviceMacWithTag,
      }),
    })
  }
}
