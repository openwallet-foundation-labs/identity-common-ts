import { CoseKey, type DigestAlgorithm, type SignatureAlgorithm } from '@owf/cose'
import type { MdocContext } from './context'
import type {
  DeviceKeyInfo,
  DeviceKeyInfoOptions,
  DocType,
  IssuerSigned,
  Namespace,
  Status,
  StatusOptions,
  ValidityInfo,
  ValidityInfoOptions,
} from './mdoc'
import { IssuerSignedBuilder } from './mdoc/builders'

export class Issuer {
  private isb: IssuerSignedBuilder

  public constructor(docType: DocType, ctx: Pick<MdocContext, 'cose' | 'crypto'>) {
    this.isb = new IssuerSignedBuilder(docType, ctx)
  }

  public addIssuerNamespace(namespace: Namespace, value: Record<string | number, unknown>) {
    this.isb = this.isb.addIssuerNamespace(namespace, value)
    return this
  }

  public async sign(options: {
    signingKey: CoseKey | Record<string | number, unknown>
    algorithm: SignatureAlgorithm
    digestAlgorithm: DigestAlgorithm
    validityInfo: ValidityInfo | ValidityInfoOptions
    deviceKeyInfo: DeviceKeyInfo | DeviceKeyInfoOptions
    certificates: Uint8Array[]
    /**
     * Optional Status structure to embed in the MSO. See
     * ISO/IEC 18013-5 second edition (CD), 12.3.6.
     */
    status?: Status | StatusOptions
    /**
     * Add a SHA-256 `x5t` of the leaf certificate to the protected header, as the second edition of
     * ISO/IEC 18013-5 recommends. Off by default, as the first edition has nothing but `alg` there.
     */
    includeX5t?: boolean
  }): Promise<IssuerSigned> {
    const signingKey = options.signingKey instanceof CoseKey ? options.signingKey : CoseKey.fromJwk(options.signingKey)
    return await this.isb.sign({ ...options, signingKey })
  }
}
